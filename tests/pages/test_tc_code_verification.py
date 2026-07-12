from unittest.mock import mock_open, patch

from . import create_ctx


TC_CODE = "123456"
TC_CODE_EXTENDED_HASH = (
    b"z\xc0\x99\xac\x01\x1f\xef\x91\xb6\xd5\xbd\xa8\xdc\xfc\x14\xcco-A"
    b"\x9d\xba\xde\xaf\xe3\xe1{@0t\xb2\x85{"
)
ALT_TC_CODE = "aBcDeF%@14"
ALT_TC_CODE_EXTENDED_HASH = (
    b"\x98\x99kJ\x03\x98r\xec \x9d\xd6\xbaG\xc2P\xbb9\x00\xe53("
    b"\x98\xb9\x1a,\x13-.\x1e\xe6Z\xc8"
)
ALT_TC_CODE_HASH = (
    b'<9y~\xba\xfdqv\xa0\xb5\x0f\xf9v6 lht\xf4\x17\xcfmw"J\xac8bkx\xc3\xfa'
)
INVALID_EXTENDED_HASH = (
    b"\x98\x99kJ\x04\x98r\xec \x9d\xd6\xbaG\xc2P\xbb9\x00\xe53("
    b"\x98\xb9\x1a,\x13-.\x1e\xe6Z\xc8"
)


def _patch_device_secret(mocker):
    mocker.patch("machine.unique_id", return_value=b"\x01" * 32)


def _assert_keypad_called_for_tc_code(tc_verifier, changing_tc_code=False):
    from krux.pages import LETTERS, NUM_SPECIAL_1, NUM_SPECIAL_2, UPPERCASE_LETTERS

    keypad_label = (
        "Current Tamper Check Code" if changing_tc_code else "Tamper Check Code"
    )
    tc_verifier.capture_from_keypad.assert_called_once_with(
        keypad_label,
        [NUM_SPECIAL_1, LETTERS, UPPERCASE_LETTERS, NUM_SPECIAL_2],
    )


def test_tc_code_input_mode_default_is_manual(amigo):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_MANUAL

    assert (
        Settings().security.tamper_check_code_input_mode
        == TAMPER_CHECK_INPUT_MANUAL
    )


def test_tc_code_verification_manual_cases(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_MANUAL
    from krux.pages.tc_code_verification import TCCodeVerification

    cases = [
        # TC Code, extended hash, expected result, changing TC Code, expected hash
        (TC_CODE, TC_CODE_EXTENDED_HASH, True, False, False),
        (ALT_TC_CODE, ALT_TC_CODE_EXTENDED_HASH, True, False, False),
        (ALT_TC_CODE, ALT_TC_CODE_EXTENDED_HASH, True, True, False),
        (ALT_TC_CODE, ALT_TC_CODE_EXTENDED_HASH, True, False, ALT_TC_CODE_HASH),
        (ALT_TC_CODE, INVALID_EXTENDED_HASH, False, False, False),
    ]
    for case in cases:
        _patch_device_secret(mocker)
        Settings().security.tamper_check_code_input_mode = TAMPER_CHECK_INPUT_MANUAL
        ctx = create_ctx(mocker, [])
        tc_verifier = TCCodeVerification(ctx)
        tc_verifier.capture_from_keypad = mocker.MagicMock(return_value=case[0])
        tc_verifier._capture_from_qr = mocker.MagicMock()

        with patch("builtins.open", mock_open(read_data=case[1])):
            if case[4]:
                assert (
                    tc_verifier.capture(changing_tc_code=case[3], return_hash=True)
                    == case[4]
                )
            else:
                assert tc_verifier.capture(changing_tc_code=case[3]) is case[2]

        _assert_keypad_called_for_tc_code(tc_verifier, case[3])
        tc_verifier._capture_from_qr.assert_not_called()


def test_tc_code_verification_scan_qr_mode(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_SCAN_QR
    from krux.pages.qr_capture import QRCodeCapture
    from krux.pages.tc_code_verification import TCCodeVerification

    _patch_device_secret(mocker)
    Settings().security.tamper_check_code_input_mode = TAMPER_CHECK_INPUT_SCAN_QR
    qr_capture_loop = mocker.patch.object(
        QRCodeCapture,
        "qr_capture_loop",
        autospec=True,
        return_value=(TC_CODE, None),
    )
    ctx = create_ctx(mocker, [])
    tc_verifier = TCCodeVerification(ctx)
    tc_verifier.capture_from_keypad = mocker.MagicMock()

    with patch("builtins.open", mock_open(read_data=TC_CODE_EXTENDED_HASH)):
        assert tc_verifier.capture() is True

    qr_capture_loop.assert_called_once()
    tc_verifier.capture_from_keypad.assert_not_called()


def test_tc_code_verification_ask_every_time_routes_manual(amigo, mocker):
    from krux.krux_settings import (
        Settings,
        TAMPER_CHECK_INPUT_ASK_EVERY_TIME,
        TAMPER_CHECK_INPUT_MANUAL,
    )
    from krux.pages.tc_code_verification import Menu, TCCodeVerification

    _patch_device_secret(mocker)
    Settings().security.tamper_check_code_input_mode = (
        TAMPER_CHECK_INPUT_ASK_EVERY_TIME
    )
    mocker.patch.object(Menu, "run_loop", return_value=(0, TAMPER_CHECK_INPUT_MANUAL))
    ctx = create_ctx(mocker, [])
    tc_verifier = TCCodeVerification(ctx)
    tc_verifier.capture_from_keypad = mocker.MagicMock(return_value=TC_CODE)
    tc_verifier._capture_from_qr = mocker.MagicMock()

    with patch("builtins.open", mock_open(read_data=TC_CODE_EXTENDED_HASH)):
        assert tc_verifier.capture() is True

    _assert_keypad_called_for_tc_code(tc_verifier)
    tc_verifier._capture_from_qr.assert_not_called()


def test_tc_code_verification_ask_every_time_routes_scan_qr(amigo, mocker):
    from krux.krux_settings import (
        Settings,
        TAMPER_CHECK_INPUT_ASK_EVERY_TIME,
        TAMPER_CHECK_INPUT_SCAN_QR,
    )
    from krux.pages.tc_code_verification import Menu, TCCodeVerification

    _patch_device_secret(mocker)
    Settings().security.tamper_check_code_input_mode = (
        TAMPER_CHECK_INPUT_ASK_EVERY_TIME
    )
    mocker.patch.object(Menu, "run_loop", return_value=(0, TAMPER_CHECK_INPUT_SCAN_QR))
    ctx = create_ctx(mocker, [])
    tc_verifier = TCCodeVerification(ctx)
    tc_verifier.capture_from_keypad = mocker.MagicMock()
    tc_verifier._capture_from_qr = mocker.MagicMock(return_value=TC_CODE)

    with patch("builtins.open", mock_open(read_data=TC_CODE_EXTENDED_HASH)):
        assert tc_verifier.capture() is True

    tc_verifier._capture_from_qr.assert_called_once()
    tc_verifier.capture_from_keypad.assert_not_called()


def test_tc_code_verification_ask_every_time_cancel(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_ASK_EVERY_TIME
    from krux.pages import ESC_KEY
    from krux.pages.tc_code_verification import Menu, TCCodeVerification

    Settings().security.tamper_check_code_input_mode = (
        TAMPER_CHECK_INPUT_ASK_EVERY_TIME
    )
    mocker.patch.object(Menu, "run_loop", return_value=(2, ESC_KEY))
    ctx = create_ctx(mocker, [])
    tc_verifier = TCCodeVerification(ctx)
    tc_verifier.capture_from_keypad = mocker.MagicMock()
    tc_verifier._capture_from_qr = mocker.MagicMock()
    open_mock = mocker.patch("builtins.open")

    assert tc_verifier.capture() is False
    tc_verifier.capture_from_keypad.assert_not_called()
    tc_verifier._capture_from_qr.assert_not_called()
    open_mock.assert_not_called()


def test_tc_code_verification_qr_valid_values(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_SCAN_QR
    from krux.pages.qr_capture import QRCodeCapture
    from krux.pages.tc_code_verification import TCCodeVerification

    cases = [
        ("valid QR str input", "  %s\n" % TC_CODE),
        ("valid QR bytes input", b"123456\r\n"),
    ]
    _patch_device_secret(mocker)
    Settings().security.tamper_check_code_input_mode = TAMPER_CHECK_INPUT_SCAN_QR
    qr_capture_loop = mocker.patch.object(
        QRCodeCapture,
        "qr_capture_loop",
        autospec=True,
        side_effect=[(case[1], None) for case in cases],
    )

    for case in cases:
        ctx = create_ctx(mocker, [])
        tc_verifier = TCCodeVerification(ctx)
        tc_verifier.capture_from_keypad = mocker.MagicMock()
        with patch("builtins.open", mock_open(read_data=TC_CODE_EXTENDED_HASH)):
            assert tc_verifier.capture() is True
        tc_verifier.capture_from_keypad.assert_not_called()

    assert qr_capture_loop.call_count == len(cases)


def test_tc_code_verification_qr_invalid_values(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_SCAN_QR
    from krux.pages.qr_capture import QRCodeCapture
    from krux.pages.tc_code_verification import TCCodeVerification

    cases = [
        ("QR capture cancellation", None),
        ("empty QR value", ""),
        ("whitespace QR value", "  \n\t  "),
        ("malformed QR bytes", b"\xff"),
        ("unexpected QR value", 123456),
        ("multiline QR value", "123\n456"),
    ]
    Settings().security.tamper_check_code_input_mode = TAMPER_CHECK_INPUT_SCAN_QR
    qr_capture_loop = mocker.patch.object(
        QRCodeCapture,
        "qr_capture_loop",
        autospec=True,
        side_effect=[(case[1], None) for case in cases],
    )
    open_mock = mocker.patch("builtins.open")

    for case in cases:
        ctx = create_ctx(mocker, [])
        tc_verifier = TCCodeVerification(ctx)
        tc_verifier.capture_from_keypad = mocker.MagicMock()
        assert tc_verifier.capture() is False
        tc_verifier.capture_from_keypad.assert_not_called()

    assert qr_capture_loop.call_count == len(cases)
    open_mock.assert_not_called()


def test_changing_tc_code_always_uses_manual_input(amigo, mocker):
    from krux.krux_settings import Settings, TAMPER_CHECK_INPUT_SCAN_QR
    from krux.pages.tc_code_verification import TCCodeVerification

    _patch_device_secret(mocker)
    Settings().security.tamper_check_code_input_mode = TAMPER_CHECK_INPUT_SCAN_QR
    ctx = create_ctx(mocker, [])
    tc_verifier = TCCodeVerification(ctx)
    tc_verifier.capture_from_keypad = mocker.MagicMock(return_value=TC_CODE)
    tc_verifier._capture_from_qr = mocker.MagicMock()

    with patch("builtins.open", mock_open(read_data=TC_CODE_EXTENDED_HASH)):
        assert tc_verifier.capture(changing_tc_code=True) is True

    _assert_keypad_called_for_tc_code(tc_verifier, changing_tc_code=True)
    tc_verifier._capture_from_qr.assert_not_called()


def test_tc_code_verification_esc_key(amigo, mocker):
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV
    from krux.pages.tc_code_verification import TCCodeVerification

    cases = [
        # Simple ESC key after entering TC Code then pressing "Yes" in prompt
        (
            BUTTON_PAGE_PREV,  # Navigate to ESC key
            BUTTON_PAGE_PREV,  # Navigate to ESC key
            BUTTON_ENTER,  # Press ESC key
            BUTTON_ENTER,  # Confirm "Yes" in prompt
        ),
        # ESC key after entering TC Code, then "No" in prompt
        # then pressing ESC again and then "Yes" to exit
        (
            BUTTON_PAGE_PREV,  # Navigate to ESC key
            BUTTON_PAGE_PREV,  # Navigate to ESC key
            BUTTON_ENTER,  # Press ESC key (first time)
            BUTTON_PAGE_PREV,  # Navigate to "No" in prompt
            BUTTON_ENTER,  # Select "No" - stay in keypad
            BUTTON_ENTER,  # Press ESC key again (cursor stays on ESC)
            BUTTON_ENTER,  # Select "Yes" - exit (default selection)
        ),
    ]

    for case in cases:
        ctx = create_ctx(mocker, case)
        tc_verifier = TCCodeVerification(ctx)
        result = tc_verifier.capture()

        assert result is False
        assert ctx.input.wait_for_button.call_count == len(case)
