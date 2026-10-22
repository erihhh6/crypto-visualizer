"""
Colours shared by several widgets.

The app is dark-only for now (see gui/main_window.py), so these are dark
theme colours.
"""

from modules.key_exchange import Actor, Visibility

COLOUR_SURFACE = "#1E1E2E"  # drawing areas: the block canvas, the image demo
COLOUR_PANEL = "#2A2A3E"  # read-only text: block details, mode comparison cards

# Key exchange: who acts (step cards, plotted points) and who may know a value.
ACTOR_COLOURS = {
    Actor.ALICE: "#5B9BD5",
    Actor.BOB: "#E07B39",
    Actor.BOTH: "#5BAD72",
    Actor.SYSTEM: "#9B59B6",
}
VALUE_COLOURS = {
    Visibility.PUBLIC: "#27AE60",
    Visibility.SHARED_SECRET: "#E74C3C",
    Visibility.PRIVATE: "#AAAAAA",
}
