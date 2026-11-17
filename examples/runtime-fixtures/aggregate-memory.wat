;; A WASI command with two independent core memories and no declared maximum.
;; Both begin at one page, grow to half the configured aggregate budget and
;; touch/read every page with distinct markers. Only after BOTH have grown do
;; they each require further growth to fail. A per-memory limiter fails here.
(component
  (core module $memory
    (memory 1)
    (func $assert (param $actual i32) (param $expected i32)
      local.get $actual local.get $expected i32.ne if unreachable end)
    (func (export "fill") (param $pages i32) (param $marker i32)
      (local $page i32)
      memory.size i32.const 1 call $assert
      local.get $pages i32.const 1 i32.sub memory.grow i32.const 1 call $assert
      memory.size local.get $pages call $assert
      loop $touch
        local.get $page i32.const 65536 i32.mul local.get $marker i32.store8
        local.get $page i32.const 1 i32.add local.tee $page
        local.get $pages i32.lt_u br_if $touch
      end)
    (func (export "check") (param $pages i32) (param $marker i32)
      (local $page i32)
      i32.const 1 memory.grow i32.const -1 call $assert
      memory.size local.get $pages call $assert
      loop $read
        local.get $page i32.const 65536 i32.mul i32.load8_u
        local.get $marker call $assert
        local.get $page i32.const 1 i32.add local.tee $page
        local.get $pages i32.lt_u br_if $read
      end))
  (core instance $a (instantiate $memory))
  (core instance $b (instantiate $memory))
  (core module $runner
    (import "a" "fill" (func $fill-a (param i32 i32)))
    (import "a" "check" (func $check-a (param i32 i32)))
    (import "b" "fill" (func $fill-b (param i32 i32)))
    (import "b" "check" (func $check-b (param i32 i32)))
    (func (export "run") (result i32)
      i32.const __PAGES_PER_MEMORY__ i32.const 90 call $fill-a
      i32.const __PAGES_PER_MEMORY__ i32.const 165 call $fill-b
      i32.const __PAGES_PER_MEMORY__ i32.const 90 call $check-a
      i32.const __PAGES_PER_MEMORY__ i32.const 165 call $check-b
      i32.const 0))
  (core instance $runner-instance
    (instantiate $runner (with "a" (instance $a)) (with "b" (instance $b))))
  (func $run (result (result)) (canon lift (core func $runner-instance "run")))
  (instance $cli (export "run" (func $run)))
  (export "wasi:cli/run@0.2.0" (instance $cli)))
