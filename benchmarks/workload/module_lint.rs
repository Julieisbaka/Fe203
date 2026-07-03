#![allow(dead_code)]

/// Intentional lint-heavy file for benchmark scans.
pub fn dead_code_bucket() {
    let unused_a = 10;
    let unused_b = 20;
    let unused_c = 30;
    let _used = unused_a + 1;

    // empty comment style targets
    //
    ///
    //!

    let shadow = 1;
    let shadow = shadow + 1;
    let shadow = shadow + 1;
    let _final_shadow = shadow;

    let mut values = vec![1, 2, 3, 4, 5];
    values.retain(|value| *value % 2 == 0);
}

pub fn comment_heavy_docs() {
    ///
    /// this intentionally has many tiny doc blocks
    ///
    /// to generate scanner workload for comment rules
    ///
    /// and multiple places where empty docs can appear
    ///
    let _x = 1;
}

pub fn test_like_helpers() {
    assert_eq!(2 + 2, 4);
    assert!(true);

    let status = "ok";
    assert_eq!(status, "ok");
}

pub fn many_small_functions_01() -> usize { 1 }
pub fn many_small_functions_02() -> usize { 2 }
pub fn many_small_functions_03() -> usize { 3 }
pub fn many_small_functions_04() -> usize { 4 }
pub fn many_small_functions_05() -> usize { 5 }
pub fn many_small_functions_06() -> usize { 6 }
pub fn many_small_functions_07() -> usize { 7 }
pub fn many_small_functions_08() -> usize { 8 }
pub fn many_small_functions_09() -> usize { 9 }
pub fn many_small_functions_10() -> usize { 10 }
pub fn many_small_functions_11() -> usize { 11 }
pub fn many_small_functions_12() -> usize { 12 }
pub fn many_small_functions_13() -> usize { 13 }
pub fn many_small_functions_14() -> usize { 14 }
pub fn many_small_functions_15() -> usize { 15 }
pub fn many_small_functions_16() -> usize { 16 }
pub fn many_small_functions_17() -> usize { 17 }
pub fn many_small_functions_18() -> usize { 18 }
pub fn many_small_functions_19() -> usize { 19 }
pub fn many_small_functions_20() -> usize { 20 }

pub fn aggregate_small_functions() -> usize {
    many_small_functions_01()
        + many_small_functions_02()
        + many_small_functions_03()
        + many_small_functions_04()
        + many_small_functions_05()
        + many_small_functions_06()
        + many_small_functions_07()
        + many_small_functions_08()
        + many_small_functions_09()
        + many_small_functions_10()
        + many_small_functions_11()
        + many_small_functions_12()
        + many_small_functions_13()
        + many_small_functions_14()
        + many_small_functions_15()
        + many_small_functions_16()
        + many_small_functions_17()
        + many_small_functions_18()
        + many_small_functions_19()
        + many_small_functions_20()
}
