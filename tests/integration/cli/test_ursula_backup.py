import os

from nucypher.config.storages import LocalFileBasedNodeStorage
from nucypher.cli.commands.ursula import ursula as ursula_command


def test_ursula_backup_and_restore_config(click_runner, lonely_ursula_maker, tmpdir):
    domain = "fake_domain"
    password = "password"

    # Create directory structure for local node
    backup_dir = tmpdir.mkdir("my_backups")
    backup_path = backup_dir / "my_backup.zip"

    keystore_dir_name = "my_keystore"
    keystore_dir = tmpdir.mkdir(keystore_dir_name)
    keystore_file = "keystore.json"
    with open(keystore_dir / keystore_file, "w") as f:
        f.write("{'this_is': 'a_fake_keystore_file'}")

    worker_dir_name = "my_workers"
    worker_dir = tmpdir.mkdir(worker_dir_name)
    known_nodes = worker_dir.mkdir("known_nodes")
    metadata = known_nodes.mkdir("metadata")
    certs = known_nodes.mkdir("certs")

    # Create local storage and pair of Urulas
    node_storage = LocalFileBasedNodeStorage(federated_only=True, metadata_dir=metadata, certificates_dir=certs,
                                             storage_root=known_nodes)
    ursula, other_ursula = lonely_ursula_maker(domain=domain, node_storage=node_storage, quantity=2,
                                               know_each_other=True, save_metadata=True)

    # Make sure one Ursula knows about the other Ursula, so that we have some files saved in local node dirs
    assert other_ursula in ursula.known_nodes

    # Backup Ursula files
    cli_args = ('backup',
                '--keystore-path', keystore_dir,
                '--worker-path', worker_dir,
                '--backup-path', backup_path,
                '--password', password)

    result = click_runner.invoke(ursula_command, cli_args, catch_exceptions=False)
    assert result.exit_code == 0
    assert backup_path.exists()

    # Crate directory structure for restored Ursula files
    restored_root = tmpdir.mkdir("restored_root")
    restored_keystore_path = restored_root / "my_restored_keystore"
    restored_worker_path = restored_root / "my_restored_worker"

    # Restore Ursula files
    cli_args = ('restore',
                '--keystore-path', restored_keystore_path,
                '--worker-path', restored_worker_path,
                '--backup-path', backup_path,
                '--password', password)

    result = click_runner.invoke(ursula_command, cli_args, catch_exceptions=False)
    assert result.exit_code == 0

    # Recreate local storage from restored files
    restored_known_nodes = restored_worker_path / worker_dir_name / "known_nodes"
    restored_metadata = restored_known_nodes / "metadata"
    restored_certs = restored_known_nodes / "certs"
    restored_node_storage = LocalFileBasedNodeStorage(federated_only=True,
                                                      metadata_dir=restored_metadata,
                                                      certificates_dir=restored_certs,
                                                      storage_root=restored_known_nodes)

    # Recreate Ursulas
    restored_ursula, other_restored_ursula = lonely_ursula_maker(domain=domain, node_storage=restored_node_storage,
                                                                 quantity=2, know_each_other=True, save_metadata=False)
    assert other_restored_ursula in restored_ursula.known_nodes

    assert keystore_file in os.listdir(restored_keystore_path / keystore_dir_name)
