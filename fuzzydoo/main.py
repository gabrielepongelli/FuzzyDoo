import sys
import os
import logging
from pathlib import Path
from collections.abc import Callable
from argparse import ArgumentParser, FileType, RawTextHelpFormatter, _SubParsersAction, ArgumentError, Namespace
from typing import Any, NoReturn, cast

import yaml


######
# Configurations and default values
######

PROGRAM_NAME = 'fuzzydoo'
PROGRAM_DESCRIPTION = 'Command line tool for fuzzing 5G core networks and network functions.'
REPLAY_EXAMPLES = f"""Examples:
    Replay all the 2-nd run using the seed 0x12345678: '{PROGRAM_NAME} replay ./config.yaml 0x12345678 2'
    Replay the 4-th epoch of the 1-st run using the seed 0x12345678: '{PROGRAM_NAME} replay ./config.yaml 0x12345678 1 --epoch 4'
    Replay the 27-th test-case of the 9-th epoch of the 3-rd run using the seed 0x12345678: '{PROGRAM_NAME} replay ./config.yaml 0x12345678 3 --epoch 9 --test-case 27'
"""

DEFAULT_OUTPUT_DIR = Path.cwd() / 'out'
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_TESTS_PER_EPOCH = 40
DEFAULT_STOP_ON_FIND = False
DEFAULT_MAX_WAIT_TIME = 60
DEFAULT_LOG_LEVEL = 'info'


######
# Helper classes and functions
######

class CustomCmdHelpFormatter(RawTextHelpFormatter):
    """A custom formatter for argparse help messages.

    This formatter extends the default `RawTextHelpFormatter` to provide the following enhancements:
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

    if attr_name != "" and attr_name not in config:
        err(f"missing '{attr_name}' attribute")

    to_check = config if attr_name == "" else config[attr_name]
    if not isinstance(to_check, attr_type):
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

        if attr_name == "":
            err(f"the data should be {attr_type}")
        else:
            err(f"the '{attr_name}' attribute should be {attr_type}")


def parse_agent(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> tuple | NoReturn:
    """Parse an agent configuration.

    Args:
        conf: The configuration dictionary for the agent, which must include a `'name'` key.
        refs: A dictionary to store references to created agents, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        tuple | NoReturn: A tuple containing the created `Agent` instance and a dictionary of 
            options. If an error occurs during parsing or agent creation, the function calls the 
            error handler.
    """

    from fuzzydoo.agent import Agent, AgentError

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


def parse_publisher(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> list[tuple] | NoReturn:
    """Parse a publisher configuration.

    Args:
        conf: The configuration dictionary for the publisher, which must include a `'name'` and
            `'actors'` key.
        refs: A dictionary to store references to created publishers, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        list[tuple] | NoReturn: A list of tuples where each tuple contains an actor name and a 
            `Publisher` instance. If an error occurs during parsing or publisher creation, the 
            function calls the error handler.
    """

    from fuzzydoo.publisher import Publisher, PublisherSource, PublisherError

    check_attr(conf, 'name', str, err)
    check_attr(conf, 'actors', list, err)

    for actor in conf['actors']:
        check_attr({'actor': actor}, 'actor', str, err)

    res = []
    if 'ref' in conf:
        check_attr(conf, 'ref', int, err)
        if conf['ref'] in refs:
            p = refs[conf['ref']]
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
                err(f"invalid publisher '{conf['name']}' with reference '{conf['ref']}'")
            return res
        else:
            err(f"invalid reference value: {conf['ref']}")

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


def parse_encoder(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> Any | NoReturn:
    """Parse an encoder configuration.

    Args:
        conf: The configuration dictionary for the encoder, which must include a `'name'` key.
        refs: A dictionary to store references to created encoders, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        Any | NoReturn: The new `Encoder` instance. If an error occurs during parsing 
            or encoder creation, the function calls the error handler.
    """

    from fuzzydoo.transformer import Encoder, TransformerError

    check_attr(conf, 'name', str, err)

    if 'ref' in conf:
        check_attr(conf, 'ref', int, err)
        if conf['ref'] in refs:
            enc = refs[conf['ref']]
            if isinstance(enc, Encoder):
                return enc
            err(f"invalid encoder '{conf['name']}' with reference '{conf['ref']}'")
        else:
            err(f"invalid reference value: {conf['ref']}")

    if 'configs' in conf:
        check_attr(conf, 'configs', dict, err)
        args = conf['configs']
    else:
        args = {}

    try:
        enc = Encoder.from_name(conf['name'], **args)
    except TransformerError as e:
        err(str(e))

    if 'id' in conf:
        refs[conf['id']] = enc

    return enc


def parse_decoder(conf: dict, refs: dict[int, Any], err: Callable[[str], NoReturn]) -> Any | NoReturn:
    """Parse a decoder configuration.

    Args:
        conf: The configuration dictionary for the decoder, which must include a `'name'` key.
        refs: A dictionary to store references to created decoders, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        Any | NoReturn: The new `Decoder` instance. If an error occurs during parsing 
            or decoder creation, the function calls the error handler.
    """

    from fuzzydoo.transformer import Decoder, TransformerError

    check_attr(conf, 'name', str, err)

    if 'ref' in conf:
        check_attr(conf, 'ref', int, err)
        if conf['ref'] in refs:
            dec = refs[conf['ref']]
            if isinstance(dec, Decoder):
                return dec
            err(f"invalid decoder '{conf['name']}' with reference '{conf['ref']}'")
        else:
            err(f"invalid reference value: {conf['ref']}")

    if 'configs' in conf:
        check_attr(conf, 'configs', dict, err)
        args = conf['configs']
    else:
        args = {}

    try:
        dec = Decoder.from_name(conf['name'], **args)
    except TransformerError as e:
        err(str(e))

    if 'id' in conf:
        refs[conf['id']] = dec

    return dec


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


def resolve_references(references: list[list[list, int, list, Callable]]) -> None | NoReturn:
    """Try to resolve previously unresolved references.

    Args:
        references: A list of references to resolve. Each reference has the following content:
            1. The final list in which the dereferenced object should be placed.
            2. The index in the final list where the dereferenced object should be placed.
            3. A list of arguments to pass to the parser function when resolving the reference.
            4. A parser function to use to resolve the reference.
    """

    if len(references) == 0:
        return

    for i, ref in enumerate(references):
        final_list, idx, args, parse = ref[0], ref[1], ref[2], ref[3]
        solved_ref = parse(*args)
        if isinstance(solved_ref, list):
            final_list[idx] = solved_ref[0]
            for j, r in enumerate(solved_ref[1:]):
                final_list.insert(idx + j + 1, r)
            for r in references[i + 1:]:
                if r[0] is final_list:
                    r[1] = r[1] + len(solved_ref) - 1
        else:
            final_list[idx] = solved_ref


def parse_run(conf: dict, err: Callable[[str], NoReturn]) -> dict[str, Any] | NoReturn:
    """Parse a decoder configuration.

    Args:
        conf: The configuration dictionary for the decoder, which must include a `'name'` key.
        refs: A dictionary to store references to created decoders, indexed by their IDs.
        err: A callable that handles error messages, typically by raising an exception.

    Returns:
        Decoder | NoReturn: The new `Decoder` instance. If an error occurs during parsing 
            or decoder creation, the function calls the error handler.
    """

    from fuzzydoo.protocol import Protocol, ProtocolError
    from fuzzydoo.transformer import Encoder, Decoder
    from fuzzydoo.agent import Agent
    from fuzzydoo.publisher import Publisher

    res = {}

    check_attr(conf, 'protocol_name', str, err)
    try:
        res['protocol'] = Protocol.from_name(conf['protocol_name'])
    except ProtocolError as e:
        try:
            res['protocol'] = Protocol.from_name(conf['protocol_name'].upper())
        except ProtocolError:
            try:
                res['protocol'] = Protocol.from_name(conf['protocol_name'].lower())
            except ProtocolError:
                err(str(e))

    check_attr(conf, 'actor', str, err)
    for actor in res['protocol'].actors:
        if conf['actor'].lower() == actor.lower():
            res['actor'] = actor
            break
    else:
        err(f"invalid actor '{conf['actor']}'")

    refs: dict[int, Any] = {}
    to_resolve_later: list[list[list, int, dict, list, Callable]] = []
    agents: list[tuple[Agent, dict]] = []
    if 'agents' in conf:
        check_attr(conf, 'agents', list, err)
        for i, agent in enumerate(conf['agents']):
            err_prefix = f"agent {i + 1}: "
            custom_err = lambda msg: err(err_prefix + msg)
            agents.append(parse_agent(agent, refs, custom_err))
    res['agents'] = agents

    publishers: list[tuple[str, Publisher]] = []
    check_attr(conf, 'publishers', list, err)
    for i, pub in enumerate(conf['publishers']):
        err_prefix = f"publisher {i + 1}: "
        custom_err = lambda msg: err(err_prefix + msg)
        args = [pub, refs, custom_err]
        if 'ref' in pub and pub['ref'] not in refs:
            to_resolve_later.append([publishers, i, args, parse_publisher])
            publishers.append(None)
        else:
            publishers.extend(parse_publisher(*args))

    encoders: list[Encoder] = []
    if 'encoders' in conf:
        check_attr(conf, 'encoders', list, err)
        for i, enc in enumerate(conf['encoders']):
            err_prefix = f"encoders {i + 1}: "
            custom_err = lambda msg: err(err_prefix + msg)
            args = [enc, refs, custom_err]
            if 'ref' in enc and enc['ref'] not in refs:
                to_resolve_later.append([encoders, i, args, parse_encoder])
                encoders.append(None)
            else:
                encoders.append(parse_encoder(*args))
    res['encoders'] = encoders

    decoders: list[Decoder] = []
    if 'decoders' in conf:
        check_attr(conf, 'decoders', list, err)
        for i, dec in enumerate(conf['decoders']):
            err_prefix = f"decoders {i + 1}: "
            custom_err = lambda msg: err(err_prefix + msg)
            args = [dec, refs, custom_err]
            if 'ref' in dec and dec['ref'] not in refs:
                to_resolve_later.append([decoders, i, args, parse_decoder])
                decoders.append(None)
            else:
                decoders.append(parse_decoder(*args))
    res['decoders'] = decoders

    resolve_references(to_resolve_later)

    actors: dict[str, Publisher] = {}
    check_attr(conf, 'actors', list, err)
    for i, actor in enumerate(conf['actors']):
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

    set_optional_config(src=conf, dst=res, src_name='seed', dst_name='main_seed',
                        src_type=int, default=lambda: generate_main_seed(err), err=err)

    set_optional_config(src=conf, dst=res, src_name='output_dir', dst_name='findings_dir_path',
                        src_type=str, default=DEFAULT_OUTPUT_DIR, err=err)
    res['findings_dir_path'] = Path(res['findings_dir_path'])

    set_optional_config(src=conf, dst=res, src_name='max_attempts',
                        dst_name='max_attempts_of_test_redo',
                        src_type=int, default=DEFAULT_MAX_ATTEMPTS, err=err)

    set_optional_config(src=conf, dst=res, src_name='tests_per_epoch',
                        dst_name='max_test_cases_per_epoch',
                        src_type=int, default=DEFAULT_TESTS_PER_EPOCH, err=err)

    set_optional_config(src=conf, dst=res, src_name='stop_on_find',
                        dst_name='stop_on_find',
                        src_type=bool, default=DEFAULT_STOP_ON_FIND, err=err)

    set_optional_config(src=conf, dst=res, src_name='max_wait_time',
                        dst_name='wait_time_before_test_end',
                        src_type=int, default=DEFAULT_MAX_WAIT_TIME, err=err)

    return res


def parse_configs(file: FileType, err: Callable[[str], NoReturn]) -> dict[str, list[dict[str, Any] | Any]] | NoReturn:
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
        dict[str, list[dict[str, Any] | Any]] | NoReturn: A dictionary containing the parsed 
            configuration data in the following format:
                - `'agents'`: A list of all the agents involved in all the runs.
                - `'runs'`: The parsed configuration data for each run.
          If an error occurs during parsing, the function calls the error handler function with an 
          appropriate error message.
    """

    from fuzzydoo.agent import Agent

    try:
        configs = yaml.safe_load(file)
    except yaml.YAMLError as e:
        err(str(e))

    check_attr(configs, 'configs', dict, err)
    res: dict[str, list[Agent | dict[Any]]] = {
        'agents': [],
        'runs': []
    }

    check_attr(configs['configs'], 'runs', list, err)
    for i, run in enumerate(configs['configs']['runs']):
        err_prefix = f"run {i + 1}: "
        custom_err = lambda msg: err(err_prefix + msg)
        check_attr(configs['configs']['runs'][i], '', dict, custom_err)
        res['runs'].append(parse_run(run, custom_err))

    for run in res['runs']:
        for agent, _ in cast(list[tuple[Agent, Any]], run['agents']):
            if next((a for a in res['agents'] if a.name == agent.name), None) is None:
                res['agents'].append(agent)

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


def check(parser: ArgumentParser, sub: ArgumentParser, args: Namespace) -> None:
    """Validate configurations.

    Parameters:
        parser: The parser for the command-line arguments.
        sub: The subparser for the `'check'` command.
        args: The parsed command-line arguments.

    The function parses the configuration file and extracts the necessary arguments for the 
    `Engine` class.
    """

    err = lambda msg: error(parser, sub, msg)
    parse_configs(args.config, lambda msg: err('conf: ' + msg))


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

    from fuzzydoo.agent import Agent, AgentError
    from fuzzydoo.engine import Engine

    if args.log_level is not None:
        configure_logging(args.log_level)

    err = lambda msg: error(parser, sub, msg)
    run_data = parse_configs(args.config, lambda msg: err('conf: ' + msg))
    logging.info("Config file parsed successfully")

    try:
        for n, run in enumerate(run_data['runs']):
            logging.info("Run #%s started", n + 1)
            agents: list[tuple[Agent, dict]] = run.get('agents', [])
            for i, agent_record in enumerate(agents):
                agent, options = agent_record
                logging.debug('Setting options for agent %s', agent.name)
                try:
                    agent.set_options(**options)
                except AgentError as e:
                    logging.critical("%s", e)
                    sys.exit(1)
                run['agents'][i] = agent

            engine = Engine(**run)
            engine.run()
            logging.info("Run #%s terminated", n + 1)
    except KeyboardInterrupt:
        logging.info("Interrupted, terminating all agents...")
        for agent in cast(list[Agent], run_data['agents']):
            agent.on_test_end()
        logging.info("Run #%s terminated", n + 1)

    for agent in cast(list[Agent], run_data['agents']):
        agent.on_shutdown()


def replay(parser: ArgumentParser, sub: ArgumentParser, args: Namespace) -> None:
    """Replay a run/epoch/test case.

    Parameters:
        parser: The parser for the command-line arguments.
        sub: The subparser for the `'replay'` command.
        args: The parsed command-line arguments.

    The function performs the following steps:
    1. If a log level is provided in the command-line arguments, it configures the logging system.
    2. Parses the configuration file and extracts the necessary arguments for the `Engine` class.
    3. Iterates through the agents and sets their options.
    4. Creates an Engine instance with the extracted arguments and runs it.
    """

    from fuzzydoo.agent import Agent, AgentError
    from fuzzydoo.engine import Engine

    err = lambda msg: error(parser, sub, msg)
    if args.test_case and not args.epoch:
        err('you must specify the epoch to which the test case belongs to')

    if args.log_level is not None:
        configure_logging(args.log_level)

    run_data = parse_configs(args.config, lambda msg: err('conf: ' + msg))
    if args.run <= 0 or args.run > len(run_data['runs']):
        err('invalid run specified')

    logging.info("Config file parsed successfully")

    try:
        n = args.run - 1
        test_case = args.test_case - 1 if args.test_case is not None else None
        run: dict[str, Any] = run_data['runs'][n]
        logging.info("Run #%s started", args.run)
        agents: list[tuple[Agent, dict]] = run.get('agents', [])
        for i, agent_record in enumerate(agents):
            agent, options = agent_record
            logging.debug('Setting options for agent %s', agent.name)
            try:
                agent.set_options(**options)
            except AgentError as e:
                logging.critical("%s", e)
                sys.exit(1)
            run['agents'][i] = agent

        engine = Engine(**run)
        engine.replay(args.epoch - 1, args.seed, test_case)
        logging.info("Run #%s terminated", args.run)
    except KeyboardInterrupt:
        logging.info("Interrupted, terminating all agents...")
        for agent, _ in cast(list[tuple[Agent, Any]], run.get('agents', [])):
            agent.on_test_end()
        logging.info("Run #%s terminated", args.run)

    for agent, _ in cast(list[tuple[Agent, Any]], run.get('agents', [])):
        agent.on_shutdown()


def add_common_options(parser: ArgumentParser, with_logs: bool = True):
    """Add all the options that are common to all the parsers.

    This function will add the following options to `parser`:
    1. The help option.
    2. The log level option.

    Args:
        parser: The parser to add the common options to.
        with_logs (optional): Whether to include the log level option in the parser. Defaults to `True`.
    """

    parser.add_argument('-h', '--help', action='help',
                        help='Show this help message and exit')

    if with_logs:
        log_lvl_choices = ['debug', 'info', 'warning', 'error']
        log_lvl_help_msg = f'Set the logging level ({", ".join(
            [f'"{l}"' for l in log_lvl_choices])}) (default: "{DEFAULT_LOG_LEVEL}")'
        parser.add_argument('-l', '--log-level', choices=log_lvl_choices,
                            help=log_lvl_help_msg, default=DEFAULT_LOG_LEVEL, metavar='LEVEL')


def remove_positionals_from_help(parser: ArgumentParser):
    """Remove the `positional arguments`' section from the help output.

    Args:
        parser: The parser to modify.
    """

    # pylint: disable=protected-access
    parser._action_groups = [g for g in parser._action_groups if g.title != 'positional arguments']


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
        usage="%(prog)s COMMAND [OPTIONS]",
        epilog="Run '%(prog)s COMMAND --help' for more information on a command.",
        exit_on_error=False,
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser._optionals.title = parser._optionals.title.capitalize()

    subparsers = parser.add_subparsers(
        required=True, title='Commands', metavar='COMMAND')

    # 'fuzz' subcommand options
    parser_fuzz = subparsers.add_parser(
        name='fuzz',
        help='Start the fuzzing process',
        description='Start the fuzzing process from a configuration file.',
        add_help=False,
        usage=f"{PROGRAM_NAME} fuzz CONFIG_FILE [OPTIONS]",
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser_fuzz._optionals.title = parser_fuzz._optionals.title.capitalize()
    parser_fuzz.add_argument('config', type=FileType('r', encoding='utf8'), metavar='CONFIG_FILE')
    add_common_options(parser_fuzz)
    parser_fuzz.set_defaults(func=lambda args: fuzz(parser, parser_fuzz, args))
    remove_positionals_from_help(parser_fuzz)

    # 'check' subcommand options
    parser_check = subparsers.add_parser(
        name='check',
        help='Check configurations',
        description='Check that the configuration file provided is valid. If it is not valid, an error message will be printed.',
        add_help=False,
        usage=f"{PROGRAM_NAME} check CONFIG_FILE [OPTIONS]",
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser_check._optionals.title = parser_check._optionals.title.capitalize()
    parser_check.add_argument('config', type=FileType('r', encoding='utf8'), metavar='CONFIG_FILE')
    add_common_options(parser_check, with_logs=False)
    parser_check.set_defaults(func=lambda args: check(parser, parser_check, args))
    remove_positionals_from_help(parser_check)

    # 'replay' subcommand options
    parser_replay = subparsers.add_parser(
        name='replay',
        help='Re-perform tests',
        description='Re-perform a run/epoch/test case.',
        add_help=False,
        epilog=REPLAY_EXAMPLES,
        usage=f"{PROGRAM_NAME} replay CONFIG_FILE SEED RUN [OPTIONS]",
        formatter_class=CustomCmdHelpFormatter
    )
    # pylint: disable=protected-access
    parser_replay._optionals.title = parser_replay._optionals.title.capitalize()
    parser_replay.add_argument('config', type=FileType('r', encoding='utf8'), metavar='CONFIG_FILE')
    parser_replay.add_argument('seed', type=lambda n: int(n, 0), metavar='SEED')
    parser_replay.add_argument('run', type=int, metavar='RUN')
    add_common_options(parser_replay)
    parser_replay.add_argument('-e', '--epoch', type=int,
                               help='The number of the epoch inside the specified run to replay')
    parser_replay.add_argument('-tc', '--test-case', type=int,
                               help='The number of the test case inside the specified epoch to replay')
    parser_replay.set_defaults(func=lambda args: replay(parser, parser_replay, args))
    remove_positionals_from_help(parser_replay)

    try:
        args = parser.parse_args()
        args.func(args)
    except ArgumentError as e:
        # extract the subcommand name (if any)
        for arg in sys.argv[1:]:
            if arg in subparsers.choices:
                error(parser, subparsers.choices[arg], str(e))
        parser.print_help()
        sys.exit(1)
