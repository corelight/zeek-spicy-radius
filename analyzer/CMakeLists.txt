spicy_add_analyzer(
    NAME Radius
    PACKAGE_NAME Radius
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
