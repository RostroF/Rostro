use rostro_vm_bench::{runners::PolkaVmRunner, workloads::fib, RvmRunner};
fn main() {
    println!("Attempting PolkaVmRunner::compiler()...");
    match PolkaVmRunner::compiler() {
        Ok(mut runner) => {
            println!("OK: {}", runner.name());
            let blob = fib::polkavm_blob(1000);
            let start = std::time::Instant::now();
            let out = runner.run(&blob, &[]).expect("run");
            let elapsed = start.elapsed();
            println!("fib(1000) = {} (gas {}, time {:?})", out.result_a0, out.gas_consumed, elapsed);
        }
        Err(e) => println!("ERR: {}", e),
    }
}
