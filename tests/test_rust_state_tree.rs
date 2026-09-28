use ethos::aci::state_tree::StateTree;

#[test]
fn test_state_tree_initialization() {
    let tree = StateTree::new();
    assert_eq!(tree.current_branch(), "main");
    assert_eq!(tree.list_branches(), vec!["main"]);
}

#[test]
fn test_state_tree_commit_and_history() {
    let mut tree = StateTree::new();
    let node1 = tree.commit("snap_1", "Initial clean setup").unwrap();
    let node2 = tree.commit("snap_2", "Installed dependencies").unwrap();

    assert_eq!(node2.parent_id, Some(node1.id));
    let history = tree.get_branch_history("main");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].snapshot_id, "snap_1");
    assert_eq!(history[1].snapshot_id, "snap_2");
}

#[test]
fn test_state_tree_branching_and_switch() {
    let mut tree = StateTree::new();
    tree.commit("snap_root", "Base state").unwrap();

    // Fork a new branch to test an exploit attempt
    tree.create_branch("exploit_attempt_1").unwrap();
    assert_eq!(tree.current_branch(), "exploit_attempt_1");

    tree.commit("snap_exploit_step1", "Modified payload").unwrap();

    // Switch back to main
    tree.switch_branch("main").unwrap();
    assert_eq!(tree.current_branch(), "main");

    // Main should only have snap_root, not the exploit step
    let main_history = tree.get_branch_history("main");
    assert_eq!(main_history.len(), 1);
    assert_eq!(main_history[0].snapshot_id, "snap_root");

    let exploit_history = tree.get_branch_history("exploit_attempt_1");
    assert_eq!(exploit_history.len(), 2);
}
