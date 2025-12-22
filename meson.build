project('secure-exec-server-go', [],
        version : '0.1',
        default_options : ['warning_level=3'])


exe = custom_target('ses',
        output : 'ses',
        input : ['ses.go', 'ses_crypto.go'],
        command : ['go', 'build', '@INPUT@'],
        install : true,
        install_dir : 'bin')

test('basic', find_program('test/test_basic'), is_parallel: false)
test('shutdown', find_program('test/test_shutdown'), is_parallel: false)
test('auth_invalid_input', find_program('test/test_auth_invalid_input'), is_parallel: false)
test('auth_signature', find_program('test/test_auth_signature'), is_parallel: false)
test('keyusage', find_program('test/test_keyusage'), is_parallel: false)
test('child_process', find_program('test/test_child_process'), is_parallel: false)
test('child_parallel', find_program('test/test_child_parallel'), is_parallel: false)
test('certificates', find_program('test/test_certificates'), is_parallel: false)
