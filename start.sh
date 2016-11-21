#!/usr/bin/env bash
hjson -j osx-config.hjson > osx-config.json && python app.py --report-only

