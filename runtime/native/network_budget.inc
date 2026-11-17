// Host-only protocol: egress REVISION BOOTTIME_DEADLINE_NS CUMULATIVE_BYTES\n.
// The control plane must reserve the full granted ceiling until settled/fenced.
// Expiry stops new admissions; previously reserved writes may still complete.
static const char *network_budget_command(char *command) {
    if(!network_budget_enabled)return "egress-budget-disabled";
    char *revision=command+7,*deadline=strchr(revision,' ');
    if(!deadline)return "invalid-egress-budget";
    *deadline++=0;char *ceiling=strchr(deadline,' ');
    if(!ceiling)return "invalid-egress-budget";
    *ceiling++=0;size_t length=strlen(ceiling);
    if(!length || ceiling[length-1]!='\n')return "invalid-egress-budget";
    ceiling[length-1]=0;
    uint64_t next_revision,next_deadline,next_ceiling;
    if(!network_number(revision,&next_revision) || !next_revision ||
       !network_number(deadline,&next_deadline) || !network_number(ceiling,&next_ceiling))
        return "invalid-egress-budget";
    pthread_mutex_lock(&fd_lock);
    uint64_t now=network_now();const char *error=NULL;
    if(next_deadline && (next_deadline<=now || next_deadline-now>30000000000ull))error="invalid-egress-deadline";
    else if(next_revision<network_budget_revision)error="stale-egress-budget";
    else if(next_revision==network_budget_revision && next_ceiling!=network_budget_ceiling)error="conflicting-egress-budget";
    // A new allowance period may discard unused authority only after explicit
    // freeze and quiescence. Accepted bytes never reset; stale grants stay fenced.
    else if(next_ceiling<network_budget_ceiling &&
        (network_budget_deadline!=0 || network_tx_inflight || next_ceiling<network_tx_bytes))
        error="unsafe-egress-ceiling-reduction";
    // Revocation and renewal need distinct revisions: replaying an old grant
    // must never resurrect expired/revoked authority, even with a newer TTL.
    else if(next_revision==network_budget_revision && next_deadline!=network_budget_deadline)error="conflicting-egress-deadline";
    if(!error) {
        network_budget_revision=next_revision;network_budget_deadline=next_deadline;
        network_budget_ceiling=next_ceiling;
        if(next_deadline>now)network_budget_authorized=1;
        pthread_cond_broadcast(&network_changed);
    }
    pthread_mutex_unlock(&fd_lock);return error;
}
static void network_budget_status(char *buffer,size_t capacity) {
    pthread_mutex_lock(&fd_lock);
    snprintf(buffer,capacity,"\"egress_budget_enabled\":%s,\"egress_budget_revision\":%llu,\"egress_budget_deadline_ns\":%llu,\"egress_budget_ceiling\":%llu,\"egress_budget_reserved\":%llu,\"egress_budget_bytes\":%llu,\"egress_budget_in_flight\":%llu,\"egress_budget_measured\":%s",
        network_budget_enabled?"true":"false",(unsigned long long)network_budget_revision,
        (unsigned long long)network_budget_deadline,(unsigned long long)network_budget_ceiling,
        (unsigned long long)network_tx_reserved,(unsigned long long)network_tx_bytes,(unsigned long long)network_tx_inflight,
        network_tx_measured?"true":"false");
    pthread_mutex_unlock(&fd_lock);
}
