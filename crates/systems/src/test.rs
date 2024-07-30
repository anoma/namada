use cargo_metadata::{DependencyKind, MetadataCommand};
use lazy_static::lazy_static;
use namada_core::collections::HashSet;

lazy_static! {
    /// Namada system crate names. None of these crates are allowed to have
    /// cross-dependencies (with an exception of dev-deps).
    static ref SYSTEMS: HashSet<&'static str> =
        HashSet::from_iter([
            "namada_governance",
            "namada_parameters",
            "namada_shielded_token",
            "namada_token",
            "namada_trans_token",
        ]);
}

/// Assert that none of the `SYSTEMS` have cross dependencies.
#[test]
fn test_no_system_cross_deps() {
    let metadata = MetadataCommand::new()
        .no_deps()
        .other_options(vec!["--locked".to_string(), "--offline".to_string()])
        .exec()
        .unwrap();

    for package in metadata.packages {
        for system in SYSTEMS.iter() {
            if &package.name == system {
                for dep in package
                    .dependencies
                    .iter()
                    .filter(|d| matches!(d.kind, DependencyKind::Normal))
                {
                    for other_system in SYSTEMS.iter() {
                        // Exception for the "token" crate which puts together
                        // "trans_token" and "shielded_token".
                        if &package.name == "namada_token"
                            && (&dep.name == "namada_trans_token"
                                || &dep.name == "namada_shielded_token")
                        {
                            continue;
                        }

                        if &dep.name == other_system {
                            panic!(
                                "Forbidden cross-system dependency: {} \
                                 depends on {}",
                                system, other_system
                            );
                        }
                    }
                }
            }
        }
    }
}
