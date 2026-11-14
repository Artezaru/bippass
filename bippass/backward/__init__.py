"""
bippass - Local python password manager with Qt-GUI based on Artezaru/pyaescbc.
Copyright (C) 2026 Artezaru, artezaru.github@proton.me

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# BACKWARD COMPATIBILITY -- temporary package, to be removed (with the two
# lines marked "BACKWARD" in `GUI/window.py`) once version 2 profiles are
# no longer around. Nothing else in `core/` or `GUI/` depends on it.
#
# - `v2_to_v3`: converts a version 2 profile (`*.encrypted`) into a new
#   version 3 profile (`<uuid>.bippass`), from Python or the command line
#   (`python -m bippass.backward.v2_to_v3 <file.encrypted>`);
# - `v2_to_v3_gui`: the same, as a dialog opened from the Settings menu of
#   the start page.
