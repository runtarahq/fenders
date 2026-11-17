//! Bounded five-field cron evaluation. UTC occurrence identities are derived from
//! local wall time; repeated DST minutes select only their earlier instant.
use crate::error::{Error, Result};
use chrono::{DateTime, Datelike, Duration, LocalResult, TimeZone, Utc};
use chrono_tz::Tz;

#[derive(Debug)]
struct Field {
    values: Vec<u32>,
    wildcard: bool,
}
impl Field {
    fn parse(text: &str, min: u32, max: u32) -> Result<Self> {
        let mut values = Vec::new();
        for item in text.split(',') {
            let mut step_parts = item.split('/');
            let base = step_parts.next().unwrap_or("");
            let step_text = step_parts.next();
            if step_parts.next().is_some() {
                return Err(Error::invalid("invalid cron step"));
            }
            let number = |s: &str| -> Result<u32> {
                if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(Error::invalid(
                        "cron fields require numbers, *, ranges, lists or steps",
                    ));
                }
                s.parse()
                    .map_err(|_| Error::invalid("cron value outside field bounds"))
            };
            let step = step_text.map(number).transpose()?.unwrap_or(1);
            if step == 0 || step > max - min + 1 {
                return Err(Error::invalid("cron step outside field bounds"));
            }
            let (start, end) = if base == "*" {
                (min, max)
            } else if let Some((start, end)) = base.split_once('-') {
                (number(start)?, number(end)?)
            } else {
                let start = number(base)?;
                (start, if step_text.is_some() { max } else { start })
            };
            if start < min || end > max || end < start {
                return Err(Error::invalid("cron value outside field bounds"));
            }
            values.extend((start..=end).step_by(step as usize));
        }
        values.sort_unstable();
        values.dedup();
        Ok(Self {
            values,
            wildcard: text.starts_with('*'),
        })
    }
    fn contains(&self, value: u32) -> bool {
        self.values.binary_search(&value).is_ok()
    }
}

#[derive(Debug)]
pub struct Schedule {
    pub expression: String,
    pub timezone: Tz,
    minute: Field,
    hour: Field,
    day: Field,
    month: Field,
    weekday: Field,
}
impl Schedule {
    pub fn parse(expression: &str, timezone: &str) -> Result<Self> {
        if expression.len() > 256 || timezone.len() > 100 {
            return Err(Error::invalid("schedule configuration too long"));
        }
        let fields: Vec<_> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(Error::invalid(
                "cron requires five fields: minute hour day month weekday",
            ));
        }
        let mut weekday = Field::parse(fields[4], 0, 7)?;
        for day in &mut weekday.values {
            if *day == 7 {
                *day = 0;
            }
        }
        weekday.values.sort_unstable();
        weekday.values.dedup();
        Ok(Self {
            expression: fields.join(" "),
            timezone: timezone
                .parse()
                .map_err(|_| Error::invalid("unknown IANA timezone"))?,
            minute: Field::parse(fields[0], 0, 59)?,
            hour: Field::parse(fields[1], 0, 23)?,
            day: Field::parse(fields[2], 1, 31)?,
            month: Field::parse(fields[3], 1, 12)?,
            weekday,
        })
    }

    /// Strictly after `after`, at most 100 occurrences, searching at most eight
    /// years between occurrences (including the century leap-year gap).
    /// No wall-clock reads. Impossible expressions stop after eight years.
    pub fn next(&self, after: DateTime<Utc>, count: usize) -> Result<Vec<DateTime<Utc>>> {
        if !(1..=9999).contains(&after.year()) {
            return Err(Error::invalid(
                "schedule preview year must be between 1 and 9999",
            ));
        }
        if !(1..=100).contains(&count) {
            return Err(Error::invalid(
                "request between 1 and 100 schedule occurrences",
            ));
        }
        let mut date = after.with_timezone(&self.timezone).date_naive();
        let mut result = Vec::new();
        let mut days_without_occurrence = 0;
        while days_without_occurrence < 8 * 366 {
            let dom = self.day.contains(date.day());
            let dow = self.weekday.contains(date.weekday().num_days_from_sunday());
            let day_matches = if self.day.wildcard || self.weekday.wildcard {
                dom && dow
            } else {
                dom || dow
            };
            if self.month.contains(date.month()) && day_matches {
                for hour in &self.hour.values {
                    for minute in &self.minute.values {
                        let wall = date
                            .and_hms_opt(*hour, *minute, 0)
                            .ok_or_else(Error::internal)?;
                        let time = match self.timezone.from_local_datetime(&wall) {
                            LocalResult::Single(t) => t.with_timezone(&Utc),
                            LocalResult::Ambiguous(a, b) => a.min(b).with_timezone(&Utc),
                            LocalResult::None => continue,
                        };
                        if time > after {
                            result.push(time);
                            days_without_occurrence = 0;
                            if result.len() == count {
                                return Ok(result);
                            }
                        }
                    }
                }
            }
            date = date
                .succ_opt()
                .ok_or_else(|| Error::invalid("schedule date outside supported range"))?;
            days_without_occurrence += 1;
        }
        Err(Error::invalid(
            "not enough schedule occurrences within eight years",
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OccurrenceDisposition {
    Dispatch,
    Disabled,
    Busy,
    Missed,
    NotDue,
}

/// Eligibility at admission time, not proof of dispatch. The caller must hold
/// the app/trigger transaction lock and record the result with its occurrence ID.
pub fn disposition(
    due: DateTime<Utc>,
    now: DateTime<Utc>,
    enabled: bool,
    command_active: bool,
) -> OccurrenceDisposition {
    if !enabled {
        OccurrenceDisposition::Disabled
    } else if due > now {
        OccurrenceDisposition::NotDue
    } else if now.signed_duration_since(due) > Duration::seconds(60) {
        OccurrenceDisposition::Missed
    } else if command_active {
        OccurrenceDisposition::Busy
    } else {
        OccurrenceDisposition::Dispatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn utc(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }
    #[test]
    fn numeric_syntax_and_validation() {
        assert!(
            Schedule::parse("* * * * *", "UTC")
                .unwrap()
                .next(DateTime::<Utc>::MAX_UTC, 1)
                .is_err()
        );
        let schedule = Schedule::parse("  5/20  8-10 * * 1,3,5 ", "UTC").unwrap();
        assert_eq!(schedule.expression, "5/20 8-10 * * 1,3,5");
        assert_eq!(
            schedule.next(utc("2026-10-05T08:05:00Z"), 3).unwrap(),
            vec![
                utc("2026-10-05T08:25:00Z"),
                utc("2026-10-05T08:45:00Z"),
                utc("2026-10-05T09:05:00Z")
            ]
        );
        for invalid in [
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "0 24 * * *",
            "0 0 0 * *",
            "0 0 * 13 *",
            "0 0 * * 8",
            "*/0 * * * *",
            "*/61 * * * *",
            "1-0 * * * *",
            "1,,2 * * * *",
            "1/2/3 * * * *",
            "@daily",
            "0 0 * * MON",
            "+1 * * * *",
        ] {
            assert!(
                Schedule::parse(invalid, "UTC").is_err(),
                "accepted {invalid}"
            );
        }
        assert!(Schedule::parse("* * * * *", "Invalid/Zone").is_err());
        assert!(
            Schedule::parse("0 0 30 2 *", "UTC")
                .unwrap()
                .next(utc("2026-01-01T00:00:00Z"), 1)
                .is_err()
        );
    }
    #[test]
    fn dst_gaps_skip_and_folds_use_only_earlier_instant() {
        let spring = Schedule::parse("30 2 * * *", "America/New_York").unwrap();
        assert_eq!(
            spring.next(utc("2026-03-07T08:00:00Z"), 1).unwrap(),
            vec![utc("2026-03-09T06:30:00Z")]
        );
        let fall = Schedule::parse("30 1 * * *", "America/New_York").unwrap();
        assert_eq!(
            fall.next(utc("2026-11-01T00:00:00Z"), 2).unwrap(),
            vec![utc("2026-11-01T05:30:00Z"), utc("2026-11-02T06:30:00Z")]
        );
        assert_eq!(
            fall.next(utc("2026-11-01T05:30:01Z"), 1).unwrap(),
            vec![utc("2026-11-02T06:30:00Z")]
        );
        let zagreb = Schedule::parse("30 2 * * *", "Europe/Zagreb").unwrap();
        assert_eq!(
            zagreb.next(utc("2026-10-25T00:00:00Z"), 2).unwrap(),
            vec![utc("2026-10-25T00:30:00Z"), utc("2026-10-26T01:30:00Z")]
        );
    }
    #[test]
    fn calendar_and_day_union() {
        let union = Schedule::parse("0 9 1 * 1", "UTC").unwrap();
        assert_eq!(
            union.next(utc("2026-10-30T00:00:00Z"), 2).unwrap(),
            vec![utc("2026-11-01T09:00:00Z"), utc("2026-11-02T09:00:00Z")]
        );
        let leap = Schedule::parse("0 0 29 2 *", "UTC").unwrap();
        assert_eq!(
            leap.next(utc("2096-03-01T00:00:00Z"), 1).unwrap(),
            vec![utc("2104-02-29T00:00:00Z")]
        );
        assert_eq!(leap.next(utc("2096-03-01T00:00:00Z"), 5).unwrap().len(), 5);
        assert_eq!(
            Schedule::parse("0 0 * * 0", "UTC")
                .unwrap()
                .next(utc("2026-10-06T00:00:00Z"), 5)
                .unwrap(),
            Schedule::parse("0 0 * * 7", "UTC")
                .unwrap()
                .next(utc("2026-10-06T00:00:00Z"), 5)
                .unwrap()
        );
        let step = Schedule::parse("0 0 */2 * 1", "UTC").unwrap();
        assert_eq!(
            step.next(utc("2026-10-06T00:00:00Z"), 1).unwrap(),
            vec![utc("2026-10-19T00:00:00Z")]
        );
    }
    #[test]
    fn admission_deadline_and_priority() {
        let due = utc("2026-10-06T09:00:00Z");
        assert_eq!(
            disposition(due, due, true, false),
            OccurrenceDisposition::Dispatch
        );
        assert_eq!(
            disposition(due, due + Duration::seconds(60), true, false),
            OccurrenceDisposition::Dispatch
        );
        assert_eq!(
            disposition(due, due + Duration::seconds(61), true, false),
            OccurrenceDisposition::Missed
        );
        assert_eq!(
            disposition(due, due, true, true),
            OccurrenceDisposition::Busy
        );
        assert_eq!(
            disposition(due, due, false, true),
            OccurrenceDisposition::Disabled
        );
        assert_eq!(
            disposition(due, due - Duration::seconds(1), true, false),
            OccurrenceDisposition::NotDue
        );
    }
}
