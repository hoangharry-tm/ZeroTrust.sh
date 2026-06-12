from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

DARK_BLUE   = "1F3864"
MID_BLUE    = "2E5FA3"
LIGHT_BLUE  = "D6E4F0"
ACCENT_GOLD = "C9A84C"
WHITE       = "FFFFFF"
LIGHT_GRAY  = "F5F5F5"
MID_GRAY    = "CCCCCC"

STATUS_UNREAD   = "F5F5F5"
STATUS_READING  = "FFF3CD"
STATUS_READ     = "D6E4F0"
STATUS_REVIEWED = "D4EDDA"


def side(color=MID_GRAY, style="thin"):
    return Side(border_style=style, color=color)


def border(all_sides=MID_GRAY):
    s = side(all_sides)
    return Border(left=s, right=s, top=s, bottom=s)


def fill(hex_color):
    return PatternFill("solid", fgColor=hex_color)


def align(h="left", v="center", wrap=True):
    return Alignment(horizontal=h, vertical=v, wrap_text=wrap)
