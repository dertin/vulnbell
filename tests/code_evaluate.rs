use std::fs;

#[test]
fn independent_labels_keep_missing_observations_out_of_recall() {
    let directory = tempfile::tempdir().unwrap();
    let labels = directory.path().join("labels.json");
    let observations = directory.path().join("observations.json");
    fs::write(&labels, serde_json::json!({"schema_version":1,"cases":[
        {"id":"py-positive","language":"python","vulnerable":true,"high_priority":true,"rationale":"Untrusted input reaches the operation."},
        {"id":"rust-negative","language":"rust","vulnerable":false,"high_priority":false,"rationale":"The guard blocks the input."},
        {"id":"php-unreviewed","language":"php","vulnerable":true,"high_priority":true,"rationale":"The input is unchecked."}
    ]}).to_string()).unwrap();
    fs::write(
        &observations,
        serde_json::json!({"schema_version":1,"cases":[
            {"id":"py-positive","result":"not_found"},
            {"id":"rust-negative","result":"not_found"}
        ]})
        .to_string(),
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("vulnbell")
        .args(["tools", "code-evaluate", "--labels"])
        .arg(&labels)
        .arg("--observations")
        .arg(&observations)
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["counts"]["false_negative"], 1);
    assert_eq!(result["counts"]["true_negative"], 1);
    assert_eq!(result["counts"]["unreviewed"], 1);
    assert_eq!(result["counts"]["high_priority_missed"][0], "py-positive");
    assert_eq!(
        result["counts"]["high_priority_unreviewed"][0],
        "php-unreviewed"
    );
    assert_eq!(
        result["languages"]["php"]["recall"],
        serde_json::Value::Null
    );
}
