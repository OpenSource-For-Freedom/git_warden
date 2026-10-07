# Precision fixtures (true-positive vs false-positive)

Each `tp_*` directory is a minimal repo that MUST confirm as malicious.
Each `fp_*` directory is a minimal repo that MUST NOT confirm (legit code that
tripped a rule). `tests/test_precision_fixtures.py` runs `analyze_repo` over each
and asserts the verdict, so a rule change that re-introduces a known FP (or drops
a known TP) fails CI.

Cases are drawn from real repos surfaced by the hunt on 2026-07-07:
- fp_build_task        <- fa0311/twitter-openapi  (folderOpen venv+pip+curl maven jar)
- fp_devops_vardecode  <- mycosoftlabs/mycosoft-mas (f-string building exec(b64decode('{var}')))
- fp_webshell_tool     <- marven11/etherghost (webshell manager generating eval(base64_decode(VAR)))
- fp_scanner_selfmatch <- dnszlsk/muad-dib (a security scanner matching its own rule strings/fixtures)
- tp_dprk_folderopen   <- hvmgeeks/frontendengine1 (curl <C2> | bash on folderOpen)
- tp_literal_py_stager <- embedded base64 literal that decodes to a network dropper
- tp_marshal_stager    <- embedded marshal/zlib/base64 compiled payload
- tp_wallet_stealer_webhook <- ilyavafin/lol shape (wallet stores read and posted to a Discord webhook in one file)
- tp_polinrider_config_injection <- PolinRider v1 loader appended to postcss.config.mjs (marker, seed and _$_1e42 only; no live payload)
- tp_polinrider_v2_marker <- PolinRider v2 (Cot%3t=shtP / global['_V']='8-stN') in tailwind.config.js
- tp_polinrider_fake_font <- AgbaD/odoo shape: loader text saved as public/fonts/fa-solid-400.woff2
- tp_polinrider_npm_dep  <- ShoeVista take-home: depends on the PolinRider-published tailwindcss-style-animate
- rv_polinrider_propagation_bat <- temp_auto_push.bat alone (payload cleaned up): proof of compromise, REVIEW
- fp_polinrider_detector <- a scanner listing the PolinRider markers as detection data
- fp_font_assets         <- a real woff2 whose bytes happen to contain require( and an HTML error page saved as .woff
- fp_npm_security_placeholder <- npm's inert 0.0.1-security placeholder for a removed package
- fp_wallet_backup_tool <- wallet backup utility: reads its own Electrum store, notifies Discord from a different file

## Fixtures must never carry a live attacker host

`tp_dprk_folderopen` originally held the real C2 from the tracked campaign in a
`runOn: folderOpen` task. Opening that directory as a folder in VS Code would
have run the genuine dropper, and the repository is public, so the fixture
shipped a working weapon to anyone who cloned it.

The rules match on SHAPE, an automatic trigger plus a fetch piped into a shell,
never on a particular hostname. A `.invalid` host (reserved by RFC 2606, so it
can never resolve) tests exactly the same thing and cannot fire. Use one in any
new fixture.
