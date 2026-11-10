#[patina_dst::test(seeds = 20)]
fn results_come_back_in_job_order() {
    let results = jobs::run_all(vec![|| 1, || 2, || 3]);
    assert_eq!(results, [1, 2, 3]);
}
