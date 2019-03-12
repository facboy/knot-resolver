# daemon: lua modules

config_tests += [
  ['ta', files('trust_anchors.test/ta.test.lua')],
  ['ta_bootstrap', files('trust_anchors.test/bootstrap.test.lua')],
]

ta_config = configuration_data()
ta_config.set('keyfile_default', keyfile_default)
ta_config.set('etc_dir', etc_dir)
ta_config.set('unmanaged', managed_ta ? 'false' : 'true')

trust_anchors = configure_file(
  input: 'trust_anchors.lua.in',
  output: 'trust_anchors.lua',
  configuration: ta_config,
)
config_lua = configure_file(
  input: 'config.lua.in',
  output: 'config.lua',
  configuration: ta_config,
)

run_target(  # run manually to re-generate kres-gen.lua
  'kres-gen',
  command: find_program('./kres-gen.sh'),
)

lua_src = [
  config_lua,
  files('kres.lua'),
  files('kres-gen.lua'),
  files('sandbox.lua'),
  trust_anchors,
  files('zonefile.lua'),
]

# install daemon lua sources
install_data(
  lua_src,
  install_dir: lib_dir,
)