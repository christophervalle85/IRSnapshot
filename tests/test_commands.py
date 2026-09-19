"""Static command interpretation: collected strings are never evaluated."""
import pytest


def parse(factory, arguments, *, executable='powershell.exe', name=None):
    from irsnapshot.analyzers.commands import parse_process_command
    return parse_process_command(factory(1, name=name or executable, executable=executable, command_line=arguments))


@pytest.mark.parametrize('option', ['-EncodedCommand','-e','-en','-enc','-enco','-encodedc','-ec','/ENC','–enc','—enc','―enc'])
def test_recognized_encoded_host_options_are_case_insensitive(process_factory, option):
    facts = parse(process_factory,['powershell.exe',option,'SQBFAFgA'])
    assert [(o.name,o.value,o.token_index) for o in facts.host_options] == [('encodedcommand','SQBFAFgA',1)]
    assert facts.parse_issues == []
    assert facts.payload == []


@pytest.mark.parametrize('option', ['-w','-wi','-win','-windowstyle','/W'])
def test_window_style_host_option(process_factory, option):
    facts = parse(process_factory,['powershell.exe',option,'HiDdEn','-nop','-enc','opaque'])
    assert [(o.name,o.value) for o in facts.host_options] == [('windowstyle','HiDdEn'),('noprofile',None),('encodedcommand','opaque')]


@pytest.mark.parametrize('boundary', ['-Command','-c','-File','-f'])
def test_command_and_file_payload_are_not_reparsed_as_host_options(process_factory, boundary):
    facts = parse(process_factory,['powershell.exe','-NoProfile',boundary,'example.ps1','-enc','literal','-w','Hidden'])
    assert [o.name for o in facts.host_options] == ['noprofile', 'command' if boundary.lower() in ('-c','-command') else 'file']
    assert facts.payload == ['example.ps1','-enc','literal','-w','Hidden']
    assert facts.parse_issues == []


@pytest.mark.parametrize('option', ['-EncodedArguments','-encodeda','-ea'])
def test_encoded_arguments_are_not_encoded_command(process_factory, option):
    facts = parse(process_factory,['powershell.exe',option,'opaque'])
    assert [o.name for o in facts.host_options] == ['encodedarguments']


def test_encoded_command_consumes_only_one_value_then_more_host_options(process_factory):
    facts = parse(process_factory,['powershell.exe','-enc','opaque','-w','Hidden'])
    assert [o.name for o in facts.host_options] == ['encodedcommand','windowstyle']


@pytest.mark.parametrize('arguments', [
    ['powershell.exe','-enc'], ['powershell.exe','-w'], ['powershell.exe','-w','Purple'],
    ['powershell.exe','-enc','-windowstyle','Hidden'], ['powershell.exe','-unknown','-enc','opaque'],
    ['powershell.exe','-enc:opaque'], ['powershell.exe','--EncodedCommand','opaque'],
])
def test_unsupported_or_incomplete_host_options_do_not_invent_facts(process_factory, arguments):
    facts = parse(process_factory, arguments)
    assert facts.host_options == []
    assert facts.parse_issues


def test_script_without_explicit_file_option_is_payload(process_factory):
    facts = parse(process_factory,['pwsh.exe','example.ps1','-enc','literal'],executable='pwsh.exe')
    assert facts.host_options == []
    assert facts.payload == ['example.ps1','-enc','literal']


def test_non_powershell_retains_original_tokens_without_host_parsing(process_factory):
    facts = parse(process_factory,['cmd.exe','/c','echo','-enc'],executable='cmd.exe')
    assert facts.executable_name == 'cmd.exe'
    assert facts.host_options == []
    assert facts.payload == ['/c','echo','-enc']


def test_executable_mismatch_is_reported_and_parsing_stops(process_factory):
    facts = parse(process_factory,['powershell.exe','-enc','opaque'],executable=r'C:\Windows\System32\cmd.exe')
    assert facts.host_options == []
    assert facts.parse_issues


@pytest.mark.parametrize('arguments',[None,[]])
def test_missing_command_line_is_unknown_not_guessed(process_factory,arguments):
    facts = parse(process_factory,arguments)
    assert facts.executable_name == 'powershell.exe'
    assert facts.host_options == facts.payload == []
    assert facts.parse_issues


def test_does_not_join_then_retokenize_a_payload(process_factory):
    facts = parse(process_factory,['powershell.exe','-Command','Write-Output "-enc ignored"'])
    assert facts.payload == ['Write-Output "-enc ignored"']
    assert [o.name for o in facts.host_options] == ['command']


def test_pwsh_command_with_args_is_a_payload_boundary(process_factory):
    facts = parse(process_factory,['pwsh.exe','-cwa','echo $args','-enc','literal'], executable='pwsh.exe')
    assert facts.payload == ['echo $args','-enc','literal']
    assert [o.name for o in facts.host_options] == ['commandwithargs']


def test_option_value_is_not_a_new_switch(process_factory):
    facts = parse(process_factory,['powershell.exe','-ExecutionPolicy','Bypass','-enc','opaque'])
    assert [o.name for o in facts.host_options] == ['executionpolicy','encodedcommand']


@pytest.mark.parametrize(('raw','expected'), [
    (r'"C:\Program Files\Example\tool.exe" --flag',r'C:\Program Files\Example\tool.exe'),
    (r'C:\Windows\System32\cmd.exe /c echo test',r'C:\Windows\System32\cmd.exe'),
    (r'%SystemRoot%\System32\tool.exe --arg',r'%SystemRoot%\System32\tool.exe'),
    (r'"\\server\share\a b.exe" /flag',r'\\server\share\a b.exe'),
    ('tool.exe --flag','tool.exe'),
    ('tool.COM','tool.COM'),
    ('  "C:\\Tools\\safe.exe"  --arg',r'C:\Tools\safe.exe'),
])
def test_raw_command_target_retains_unexpanded_path(raw,expected):
    from irsnapshot.analyzers.commands import parse_command_target
    target = parse_command_target(raw)
    assert target.path == expected
    assert target.ambiguous is False
    assert target.reason


@pytest.mark.parametrize('raw', [
    '', '   ', r'C:\Program Files\Example\tool.exe -arg', r'"C:\Tool\app.exe',
    r'"C:\Tools\app.exe"suffix', '"" --arg', r'echo something', r'rundll32 javascript:example',
    'tool.exe&other.exe', 'tool.exe\x00 --arg', "'C:\\Tools\\app.exe' --flag", r'"C:\Tools\file.ps1"',
])
def test_ambiguous_raw_commands_do_not_guess_a_target(raw):
    from irsnapshot.analyzers.commands import parse_command_target
    target = parse_command_target(raw)
    assert target.path is None
    assert target.ambiguous is True
    assert target.reason


def test_pwsh_accepts_double_dash_but_does_not_scan_past_file(process_factory):
    facts = parse(process_factory, ['pwsh.exe', '--EncodedCommand', 'opaque'], executable='pwsh.exe')
    assert [o.name for o in facts.host_options] == ['encodedcommand']


def test_unicode_minus_is_not_mistaken_for_a_powershell_switch(process_factory):
    facts = parse(process_factory, ['powershell.exe', '−enc', 'opaque'])
    assert facts.host_options == []


@pytest.mark.parametrize('option', ['-worki', '-workingdir'])
def test_pwsh_working_directory_prefixes_preserve_later_options(process_factory, option):
    facts = parse(process_factory, ['pwsh.exe', option, r'C:\Tools', '-NoProfile'], executable='pwsh.exe')
    assert [(item.name, item.value) for item in facts.host_options] == [
        ('workingdirectory', r'C:\Tools'), ('noprofile', None)]
    assert facts.parse_issues == []


def test_pwsh_version_prefix_stops_host_scanning(process_factory):
    facts = parse(process_factory, ['pwsh.exe', '-ve', '-enc', 'opaque'], executable='pwsh.exe')
    assert [(item.name, item.value) for item in facts.host_options] == [('version', None)]
    assert facts.payload == ['-enc', 'opaque']
    assert facts.parse_issues == []
