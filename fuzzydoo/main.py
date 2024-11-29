import sys
import os
import logging
from pathlib import Path
from collections.abc import Callable
from argparse import ArgumentParser, FileType, HelpFormatter, _SubParsersAction, ArgumentError, Namespace
from typing import Any, NoReturn, cast

import yaml

from fuzzydoo.proto import Protocol, ProtocolError
from fuzzydoo.agent import Agent, AgentError
from fuzzydoo.publisher import Publisher, PublisherSource, PublisherError
from fuzzydoo.engine import Engine


######
# Configurations and default values
######

PROGRAM_NAME = 'fuzzydoo'
PROGRAM_DESCRIPTION = 'Command line tool for fuzzing 5G core networks and network functions.'

DEFAULT_OUTPUT_DIR = Path.cwd() / 'out'
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_TESTS_PER_EPOCH = 40
DEFAULT_STOP_ON_FIND = False
DEFAULT_MAX_WAIT_TIME = 60
DEFAULT_LOG_LEVEL = 'info'


######
# Helper classes and functions
######

class CustomCmdHelpFormatter(HelpFormatter):
    """A custom formatter for argparse help messages.

    This formatter extends the default `HelpFormatter` to provide the following enhancements:
    1. Enlarges the help text for long named arguments.
    2. Removes the choice list for subcommands in the help menu.
    3. Customizes the usage prefix.
    """

    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 24, width: int | None = None) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

        # enlarge the help text for long named arguments
        self._max_help_position = self._width

    # hack to remove the choice list for subcommands, taken from:
    # https://stackoverflow.com/questions/11070268/argparse-python-remove-subparser-list-in-help-menu

    def _format_action(self, action):
        result = super()._format_action(action)
        if isinstance(action, _SubParsersAction):
            return f"{'':{self._current_indent}}{result.lstrip()}"
        return result

    def _format_action_invocation(self, action):
        if isinstance(action, _SubParsersAction):
            return ""
        return super()._format_action_invocation(action)

    def _iter_indented_subactions(self, action):
        if isinstance(action, _SubParsersAction):
            try:
                # pylint: disable=protected-access
                get_subactions = action._get_subactions
            except AttributeError:
                pass
            else:
                yield from get_subactions()
        else:
            yield from super()._iter_indented_subactions(action)

    # hack to customize the usage prefix, taken from:
    # https://stackoverflow.com/questions/22382568/python-argparse-print-usage-text-after-description

    def _format_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = "Usage: "
        return super()._format_usage(usage, actions, groups, prefix)


class CustomLogFormatter(logging.Formatter):
    """A custom log formatter that provides a more concise and readable log format.

    This formatter extends the default `logging.Formatter` to create log messages with the
    following enhancements:
    1. Includes the logger name (capitalized) in square brackets, except for the root logger.
    2. Displays the log level in square brackets.
    3. Separates the log level from the message with a hyphen.

    The resulting format is: `[LoggerName][LEVEL] - Message`.

    For the root logger, the format is: `[LEVEL] - Message`.
    """

    def format(self, record):
        custom_format = '[%(name)s]' if record.name != 'root' else ''
        custom_format += '[%(levelname)s] - %(message)s'

        # pylint: disable=protected-access
        self._style._fmt = custom_format

        return super().format(record)


def error(parser: ArgumentParser, sub: ArgumentParser, err: str) -> NoReturn:
    """Handles errors and exit the program.

    Args:
        parser: The main argument parser.
        sub: The subcommand argument parser.
        err: The error message to be displayed.
    """

    msg = f"{sub.format_usage()}{parser.prog}: error: {err}\n"
    parser.exit(status=1, message=msg)


def check_attr(config: dict, attr_name: str, attr_type: type, err: Callable[[str], NoReturn]) -> None | NoReturn:
    """Validates the presence and type of a specified attribute in a configuration dictionary.

    Args:
        config: The configuration dictionary to check.
        attr_name: The name of the attribute to validate.
        attr_type: The expected type of the attribute.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        None | NoReturn: If the attribute is present and of the correct type, `None` will be
            returned. If the attribute is missing or of an incorrect type, the function calls the
            error handler.
    """
    if attr_name not in config:
        err(f"missing '{attr_name}' attribute")
    if not isinstance(config[attr_name], attr_type):
        if attr_type is int:
            attr_type = "a number"
        elif attr_type is str:
            attr_type = "a string"
        elif attr_type is bool:
            attr_type = "a boolean"
        elif attr_type is dict:
            attr_name = "an object"
        else:
            attr_type = "a " + str(attr_type)
        err(f"the '{attr_name}' attribute should be {attr_type}")


def parse_agent(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> tuple[Agent, dict] | NoReturn:
    """Parse an agent configuration.

    Args:
        conf: The configuration dictionary for the agent, which must include a `'name'` key.
        refs: A dictionary to store references to created agents, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        tuple[Agent, dict] | NoReturn: A tuple containing the created `Agent` instance and a
            dictionary of options. If an error occurs during parsing or agent creation, the
            function calls the error handler.
    """

    check_attr(conf, 'name', str, err)

    if 'configs' in conf:
        check_attr(conf, 'configs', dict, err)
        args = conf['configs']
    else:
        args = {}

    if 'options' in conf:
        check_attr(conf, 'options', dict, err)
        options = conf['options']
    else:
        options = {}

    try:
        a = Agent.from_name(conf['name'], **args)
    except AgentError as e:
        try:
            a = Agent.from_name(conf['name'] + 'Agent', **args)
        except AgentError:
            err(str(e))
    except TypeError as e:
        err(str(e))

    if 'id' in conf:
        check_attr(conf, 'id', int, err)
        refs[conf['id']] = a

    return (a, options)


def parse_publisher(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> list[tuple[str, Publisher]] | NoReturn:
    """Parse a publisher configuration.

    Args:
        conf: The configuration dictionary for the publisher, which must include a `'name'` and
            `'actors'` key.
        refs: A dictionary to store references to created publishers, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        list[tuple[str, Publisher]] | NoReturn: A list of tuples where each tuple contains an actor
            name and a `Publisher` instance. If an error occurs during parsing or publisher
            creation, the function calls the error handler.
    """

    check_attr(conf, 'name', str, err)
    check_attr(conf, 'actors', list, err)

    for actor in conf['actors']:
        check_attr({'actor': actor}, 'actor', str, err)

    res = []
    if 'id' in conf:
        check_attr(conf, 'id', int, err)
        if conf['id'] in refs:
            p = refs[conf['id']]
            if isinstance(p, PublisherSource):
                actors = p.actors
                for actor in conf['actors']:
                    if actor not in actors:
                        err(f"invalid actor '{actor}'")
                    res.append((actor, p.get(actor)))
            elif isinstance(p, Publisher):
                for actor in conf['actors']:
                    res.append((actor, p))
            else:
                err(
                    f"invalid publisher '{conf['name']}' with reference '{conf['id']}'")

            return res

    if 'configs' in conf:
        check_attr(conf, 'configs', dict, err)
        args = conf['configs']
    else:
        args = {}

    try:
        p = Publisher.from_name(conf['name'], **args)
    except PublisherError as e:
        err(str(e))

    if 'id' in conf:
        refs[conf['id']] = p

    for actor in conf['actors']:
        res.append((actor, p))
    return res


def generate_main_seed(err: Callable[[str], NoReturn]) -> int | NoReturn:
    """Generate a random main seed.

    Args:
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        int | NoReturn: A 64-bit random integer if the generation is successful. If an error
            occurs, it calls the error handler function with an appropriate error message.
    """

    try:
        return int.from_bytes(os.urandom(8))  # 64 bits
    except NotImplementedError as e:
        err(str(e))


def set_optional_config(
        src: dict[str, Any],
        dst: dict[str, Any],
        src_name: str,
        dst_name: str,
        src_type: type,
        default: Callable[[], Any] | Any,
        err: Callable[[str], NoReturn]) -> None | NoReturn:
    """Set an optional configuration value.

    This function performs the following operations:
    - If the configuration value is found in the source dictionary, it will be set in the
        destination dictionary.
    - If the configuration value is not found in the source dictionary, it will set the default
        value in the destination dictionary.

    Args:
        src: The source dictionary containing optional configuration values.
        dst: The destination dictionary where the resulting values will be set.
        src_name: The name of the configuration value in the source dictionary.
        dst_name: The name of the configuration value in the destination dictionary.
        src_type: The type of the configuration value.
        default: A default value to use if the configuration value is not found in the source
            dictionary. In case it is a Callable object, it will be called.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        None | NoReturn: If an error occurs during the process, it calls the error handling
            function with an appropriate error message. Otherwise, `None` will be returned.
    """
    if src_name in src:
        check_attr(src, src_name, src_type, err)
        dst[dst_name] = src[src_name]
    else:
        dst[dst_name] = default() if callable(default) else default


def parse_configs(file: FileType, err: Callable[[str], NoReturn]) -> dict[str, Any] | NoReturn:
    """Parse a configuration file.

    This function reads the configuration data from the provided file object and parses it. It then 
    validates and populates a dictionary with the parsed configuration data, ready to be used by an 
    `Engine` instance. If any errors occur during parsing or validation, the function calls the 
    provided error handler function with an appropriate error message.

    The parsed configuration data includes information about the protocol, actors, agents, 
    publishers, and other optional settings.

    Args:
        file: The file object containing the configuration data.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        dict[str, Any] | NoReturn: A dictionary containing the parsed configuration data. If an
            error occurs during parsing, the function calls the error handler function with an
            appropriate error message.
    """

    try:
        configs = yaml.safe_load(file)
    except yaml.YAMLError as e:
        err(str(e))

    check_attr(configs, 'configs', dict, err)
    run = configs['configs']
    res = {}

    check_attr(run, 'protocol_name', str, err)
    try:
        res['protocol'] = Protocol.from_name(run['protocol_name'])
    except ProtocolError as e:
        try:
            res['protocol'] = Protocol.from_name(run['protocol_name'].upper())
        except ProtocolError:
            try:
                res['protocol'] = Protocol.from_name(run['protocol_name'].lower())
            except ProtocolError:
                err(str(e))

    check_attr(run, 'actor', str, err)
    for actor in res['protocol'].actors:
        if run['actor'].lower() == actor.lower():
            res['actor'] = actor
            break
    else:
        err(f"invalid actor '{run['actor']}'")

    refs: dict[int, Any] = {}
    agents: list[tuple[Agent, dict]] = []
    if 'agents' in run:
        check_attr(run, 'agents', list, err)
        for i, agent in enumerate(run['agents']):
            err_prefix = f"agent {i + 1}: "
            custom_err = lambda msg: err(err_prefix + msg)
            agents.append(parse_agent(agent, refs, custom_err))
    res['agents'] = agents

    publishers: list[tuple[str, Publisher]] = []
    check_attr(run, 'publishers', list, err)
    for i, pub in enumerate(run['publishers']):
        err_prefix = f"publisher {i + 1}: "
        custom_err = lambda msg: err(err_prefix + msg)
        publishers.extend(parse_publisher(pub, refs, custom_err))

    actors: dict[str, Publisher] = {}
    check_attr(run, 'actors', list, err)
    for i, actor in enumerate(run['actors']):
        err_prefix = f"actor {i + 1}: "
        custom_err = lambda msg: err(err_prefix + msg)
        check_attr(actor, 'from', str, custom_err)
        check_attr(actor, 'to', str, custom_err)

        actor_from = actor['from']
        for a in res['protocol'].actors:
            if actor_from.lower() == a.lower():
                actor_from = a
                break
        else:
            custom_err(f"invalid protocol actor '{actor['from']}'")
        for a, p in publishers:
            if actor['to'] == a:
                actors[actor_from] = p
    res['actors'] = actors

    res['encoders'] = []
    res['decoders'] = []

    set_optional_config(src=run, dst=res, src_name='seed', dst_name='main_seed',
                        src_type=int, default=lambda: generate_main_seed(err), err=err)

    set_optional_config(src=run, dst=res, src_name='output_dir', dst_name='findings_dir_path',
                        src_type=str, default=DEFAULT_OUTPUT_DIR, err=err)
    res['findings_dir_path'] = Path(res['findings_dir_path'])

    set_optional_config(src=run, dst=res, src_name='max_attempts',
                        dst_name='max_attempts_of_test_redo',
                        src_type=int, default=DEFAULT_MAX_ATTEMPTS, err=err)

    set_optional_config(src=run, dst=res, src_name='tests_per_epoch',
                        dst_name='max_test_cases_per_epoch',
                        src_type=int, default=DEFAULT_TESTS_PER_EPOCH, err=err)

    set_optional_config(src=run, dst=res, src_name='stop_on_find',
                        dst_name='stop_on_find',
                        src_type=bool, default=DEFAULT_STOP_ON_FIND, err=err)

    set_optional_config(src=run, dst=res, src_name='max_wait_time',
                        dst_name='wait_time_before_test_end',
                        src_type=int, default=DEFAULT_MAX_WAIT_TIME, err=err)

    return res


def configure_logging(level: str):
    """Configure the logging system to use the specified log level.

    Args:
        level: The desired log level.
    """

    logging.basicConfig(level=level.upper())

    formatter = CustomLogFormatter()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)


def fuzz(parser: ArgumentParser, sub: ArgumentParser, args: Namespace) -> None:
    """Start the fuzzing process.

    Parameters:
        parser: The parser for the command-line arguments.
        sub: The subparser for the `'fuzz'` command.
        args: The parsed command-line arguments.

    The function performs the following steps:
    1. If a log level is provided in the command-line arguments, it configures the logging system.
    2. Parses the configuration file and extracts the necessary arguments for the `Engine` class.
    3. Iterates through the agents and sets their options.
    4. Creates an Engine instance with the extracted arguments and runs it.
    """

    if args.log_level is not None:
        configure_logging(args.log_level)

    err = lambda msg: error(parser, sub, msg)
    engine_args = parse_configs(args.config, lambda msg: err('conf: ' + msg))
    logging.info("Config file parsed successfully")
    logging.info("Main seed: %s", hex(engine_args['main_seed']))

    agents = engine_args.get('agents', [])
    for i, agent_record in enumerate(agents):
        agent, options = cast(tuple[Agent, dict], agent_record)
        logging.debug('Setting options for agent %s', agent.name)
        try:
            agent.set_options(**options)
        except AgentError as e:
            logging.critical("%s", e)
            sys.exit(1)
        engine_args['agents'][i] = agent

    engine = Engine(**engine_args)
    engine.run()


def main():
    """The main function for the fuzzing tool.

    This function sets up the command-line argument parser, adds subparsers for different commands,
    and parses the command-line arguments. It then calls the appropriate function based on the 
    command provided.
    """

    parser = ArgumentParser(
        prog=PROGRAM_NAME,
        description=PROGRAM_DESCRIPTION,
        add_help=False,
        usage="%(prog)s [OPTIONS] COMMAND",
        epilog="Run '%(prog)s COMMAND --help' for more information on a command.",
        exit_on_error=False,
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser._optionals.title = parser._optionals.title.capitalize()

    subparsers = parser.add_subparsers(
        required=True, title='Commands', metavar='COMMAND')

    # global options
    parser.add_argument('-h', '--help', action='help',
                        help='Show this help message and exit')
    log_lvl_choices = ['debug', 'info', 'warning', 'error']
    log_lvl_help_msg = f'Set the logging level ({", ".join(
        [f'"{l}"' for l in log_lvl_choices])}) (default: "{DEFAULT_LOG_LEVEL}")'
    parser.add_argument('-l', '--log-level', choices=log_lvl_choices,
                        help=log_lvl_help_msg, default=DEFAULT_LOG_LEVEL, metavar='LEVEL')

    # 'fuzz' subcommand options
    parser_fuzz = subparsers.add_parser(
        name='fuzz',
        help='Start the fuzzing process',
        description='Start the fuzzing process from a configuration file',
        add_help=False,
        usage=f"{PROGRAM_NAME} fuzz CONFIG_FILE [OPTIONS]",
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser_fuzz._optionals.title = parser_fuzz._optionals.title.capitalize()
    parser.add_argument('config', type=FileType(
        'r', encoding='utf8'), metavar='CONFIG_FILE')
    parser_fuzz.add_argument('-h', '--help', action='help',
                             help='Show this help message and exit')
    parser_fuzz.set_defaults(func=lambda args: fuzz(parser, parser_fuzz, args))

    # remove the 'positional arguments' section from the help message
    parser._action_groups = [
        g for g in parser._action_groups if g.title != 'positional arguments']

    try:
        args = parser.parse_args()
        args.func(args)
    except ArgumentError as e:
        # extract the subcommand name (if any)
        subparser = parser
        for arg in sys.argv[1:]:
            if arg in subparsers.choices:
                subparser = subparsers.choices[arg]
        error(parser, subparser, str(e))
