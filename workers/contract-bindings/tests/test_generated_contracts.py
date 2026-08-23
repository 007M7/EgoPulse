from egopulse.task.v1.task_pb2 import TaskCommand


def test_generated_task_command_round_trips() -> None:
    command = TaskCommand()
    encoded = command.SerializeToString()
    decoded = TaskCommand.FromString(encoded)
    assert decoded.WhichOneof("command") is None
