import os

from colorama import Fore, Style, init

init(autoreset=True)


class ForegroundColor:
    if os.name == "posix":
        RESET = "\033[0m"  # Reset to default text color

        # Red Variants
        RED = "\033[91m"  # Normal RED
        BRED = "\033[1;91m"  # Deep RED
        FRED = "\033[2;91m"  # Faint red
        IRED = "\033[3;91m"  # Indented RED
        LRED = "\033[4;91m"  # Underlined RED
        URED = "\033[5;91m"  # Blinking RED

        # Green Variants
        GREEN = "\033[92m"  # Normal green
        BGREEN = "\033[1;92m"  # Deep green
        FGREEN = "\033[2;92m"  # Faint green
        IGREEN = "\033[3;92m"  # Indented GREEN
        LGREEN = "\033[4;92m"  # Underlined GREEN
        UGREEN = "\033[5;92m"  # Blinking GREEN

        # Yellow Variants
        YELLOW = "\033[93m"  # Normal yellow
        BYELLOW = "\033[1;93m"  # Deep YELLOW
        FYELLOW = "\033[2;93m"  # Faint YELLOW
        IYELLOW = "\033[3;93m"  # Indented YELLOW
        LYELLOW = "\033[4;93m"  # Underlined YELLOW
        UYELLOW = "\033[5;93m"  # Blinking YELLOW

        # Blue Variants
        BLUE = "\033[94m"  # Normal BLUE
        BBLUE = "\033[1;94m"  # Deep BLUE
        FBLUE = "\033[2;94m"  # Faint Blue
        IBLUE = "\033[3;94m"  # Indented BLUE
        LBLUE = "\033[4;94m"  # Underlined BLUE
        UBLUE = "\033[5;94m"  # Blinking BLUE

        # Magenta Variants
        MAGENTA = "\033[95m"  # Normal MAGENTA
        BMAGENTA = "\033[1;95m"  # Deep MAGENTA
        FMAGENTA = "\033[2;95m"  # Faint MAGENTA
        IMAGENTA = "\033[3;95m"  # Indented MAGENTA
        LMAGENTA = "\033[4;95m"  # Underlined MAGENTA
        UMAGENTA = "\033[5;95m"  # Blinking MAGENTA

        # Cyan Variants
        CYAN = "\033[96m"  # Normal cyan
        DCYAN = "\033[1;96m"  # Deep CYAN
        FCYAN = "\033[2;96m"  # Faint cyan
        ICYAN = "\033[3;96m"  # Indented CYAN
        LCYAN = "\033[4;96m"  # Underlined CYAN
        UCYAN = "\033[5;96m"  # Blinking CYAN

        # White Variants
        BWHITE = "\033[1m"  # Bold white
        BBWHITE = "\033[5;97;1m"  # Bold Blinking white
        WHITE = "\033[97m"  # Normal white
        DWHITE = "\033[1;97m"  # Deep white
        FWHITE = "\033[2;97m"  # Faint white
        IWHITE = "\033[3;97m"  # Indented white
        LWHITE = "\033[4;97m"  # Underlined white
        UWHITE = "\033[5;97m"  # Blinking white

    if os.name == "nt":
        RESET = Style.RESET_ALL

        # Red Variants
        RED = Fore.LIGHTRED_EX
        BRED = Fore.RED
        FRED = Fore.RED
        IRED = Fore.RED
        LRED = Fore.LIGHTRED_EX  # Underlined RED
        URED = Fore.RED  # Blinking not directly supported, using RED

        # Green Variants
        GREEN = Fore.LIGHTGREEN_EX
        BGREEN = Fore.GREEN
        FGREEN = Fore.GREEN
        IGREEN = Fore.GREEN
        LGREEN = Fore.LIGHTGREEN_EX  # Underlined GREEN
        UGREEN = Fore.GREEN  # Blinking not directly supported, using GREEN

        # Yellow Variants
        YELLOW = Fore.LIGHTYELLOW_EX
        BYELLOW = Fore.YELLOW
        FYELLOW = Fore.YELLOW
        IYELLOW = Fore.YELLOW
        LYELLOW = Fore.LIGHTYELLOW_EX  # Underlined YELLOW
        UYELLOW = Fore.YELLOW  # Blinking not directly supported, using YELLOW

        # Blue Variants
        BLUE = Fore.LIGHTBLUE_EX
        BBLUE = Fore.BLUE
        FBLUE = Fore.BLUE
        IBLUE = Fore.BLUE
        LBLUE = Fore.LIGHTBLUE_EX  # Underlined BLUE
        UBLUE = Fore.BLUE  # Blinking not directly supported, using BLUE

        # Magenta Variants
        MAGENTA = Fore.LIGHTMAGENTA_EX
        BMAGENTA = Fore.MAGENTA
        FMAGENTA = Fore.MAGENTA
        IMAGENTA = Fore.LIGHTMAGENTA_EX
        LMAGENTA = Fore.LIGHTMAGENTA_EX  # Underlined MAGENTA
        UMAGENTA = Fore.MAGENTA  # Blinking not directly supported, using MAGENTA

        # Cyan Variants
        CYAN = Fore.LIGHTCYAN_EX
        DCYAN = Fore.CYAN
        ICYAN = Fore.WHITE  # Indented CYAN
        FCYAN = Fore.CYAN
        LCYAN = Fore.LIGHTCYAN_EX  # Underlined CYAN
        UCYAN = Fore.CYAN  # Blinking not directly supported, using CYAN

        # White Variants
        BWHITE = Fore.WHITE
        BBWHITE = Fore.WHITE  # Blinking not directly supported, using WHITE
        WHITE = Fore.WHITE
        DWHITE = Fore.WHITE  # Deep white (not distinct in colorama)
        FWHITE = Fore.WHITE  # Faint white (not distinct in colorama)
        IWHITE = Fore.WHITE  # Indented white (not distinct in colorama)
        LWHITE = Fore.WHITE  # Underlined white (not distinct in colorama)
        UWHITE = Fore.WHITE  # Blinking not directly supported, using WHITE


class BackgroundColor:
    if os.name == "posix":
        RESET = "\033[0m"  # Reset to default text color

        # Red Variants
        RED = "\033[91m"  # Normal RED
        BRED = "\033[1;41m"  # Deep RED
        FRED = "\033[2;41m"  # Faint red
        IRED = "\033[3;41m"  # Indented RED
        LRED = "\033[4;41m"  # Underlined RED
        URED = "\033[5;41m"  # Blinking RED

        # Green Variants
        GREEN = "\033[42m"  # Normal green
        BGREEN = "\033[1;42m"  # Deep green
        FGREEN = "\033[2;42m"  # Faint green
        IGREEN = "\033[3;42m"  # Indented GREEN
        LGREEN = "\033[4;42m"  # Underlined GREEN
        UGREEN = "\033[5;42m"  # Blinking GREEN

        # Yellow Variants
        YELLOW = "\033[43m"  # Normal yellow
        BYELLOW = "\033[1;43m"  # Deep YELLOW
        FYELLOW = "\033[2;43m"  # Faint YELLOW
        IYELLOW = "\033[3;43m"  # Indented YELLOW
        LYELLOW = "\033[4;43m"  # Underlined YELLOW
        UYELLOW = "\033[5;43m"  # Blinking YELLOW

        # Blue Variants
        BLUE = "\033[44m"  # Normal BLUE
        BBLUE = "\033[1;44m"  # Deep BLUE
        FBLUE = "\033[2;44m"  # Faint Blue
        IBLUE = "\033[3;44m"  # Indented BLUE
        LBLUE = "\033[4;44m"  # Underlined BLUE
        UBLUE = "\033[5;44m"  # Blinking BLUE

        # Magenta Variants
        MAGENTA = "\033[45m"  # Normal MAGENTA
        BMAGENTA = "\033[1;45m"  # Deep MAGENTA
        FMAGENTA = "\033[2;45m"  # Faint MAGENTA
        IMAGENTA = "\033[3;45m"  # Indented MAGENTA
        LMAGENTA = "\033[4;45m"  # Underlined MAGENTA
        UMAGENTA = "\033[5;45m"  # Blinking MAGENTA

        # Cyan Variants
        CYAN = "\033[46m"  # Normal cyan
        DCYAN = "\033[1;46m"  # Deep CYAN
        FCYAN = "\033[2;46m"  # Faint cyan
        ICYAN = "\033[3;46m"  # Indented CYAN
        LCYAN = "\033[4;46m"  # Underlined CYAN
        UCYAN = "\033[5;46m"  # Blinking CYAN

        # White Variants
        BWHITE = "\033[1m"  # Bold white
        BBWHITE = "\033[5;47;1m"  # Bold Blinking white
        WHITE = "\033[47m"  # Normal white
        DWHITE = "\033[1;47m"  # Deep white
        FWHITE = "\033[2;47m"  # Faint white
        IWHITE = "\033[3;47m"  # Indented white
        LWHITE = "\033[4;47m"  # Underlined white
        UWHITE = "\033[5;47m"  # Blinking white

        BLACK = "\033[40m"  # Black Background

    if os.name == "nt":
        RESET = Style.RESET_ALL

        # Red Variants
        RED = Fore.LIGHTRED_EX
        BRED = Fore.RED
        FRED = Fore.RED
        IRED = Fore.RED
        LRED = Fore.LIGHTRED_EX  # Underlined RED
        URED = Fore.RED  # Blinking not directly supported, using RED

        # Green Variants
        GREEN = Fore.LIGHTGREEN_EX
        BGREEN = Fore.GREEN
        FGREEN = Fore.GREEN
        IGREEN = Fore.GREEN
        LGREEN = Fore.LIGHTGREEN_EX  # Underlined GREEN
        UGREEN = Fore.GREEN  # Blinking not directly supported, using GREEN

        # Yellow Variants
        YELLOW = Fore.LIGHTYELLOW_EX
        BYELLOW = Fore.YELLOW
        FYELLOW = Fore.YELLOW
        IYELLOW = Fore.YELLOW
        LYELLOW = Fore.LIGHTYELLOW_EX  # Underlined YELLOW
        UYELLOW = Fore.YELLOW  # Blinking not directly supported, using YELLOW

        # Blue Variants
        BLUE = Fore.LIGHTBLUE_EX
        BBLUE = Fore.BLUE
        FBLUE = Fore.BLUE
        IBLUE = Fore.BLUE
        LBLUE = Fore.LIGHTBLUE_EX  # Underlined BLUE
        UBLUE = Fore.BLUE  # Blinking not directly supported, using BLUE

        # Magenta Variants
        MAGENTA = Fore.LIGHTMAGENTA_EX
        BMAGENTA = Fore.MAGENTA
        FMAGENTA = Fore.MAGENTA
        IMAGENTA = Fore.LIGHTMAGENTA_EX
        LMAGENTA = Fore.LIGHTMAGENTA_EX  # Underlined MAGENTA
        UMAGENTA = Fore.MAGENTA  # Blinking not directly supported, using MAGE

        # Cyan Variants
        CYAN = Fore.LIGHTCYAN_EX
        DCYAN = Fore.CYAN
        ICYAN = Fore.WHITE  # Indented CYAN
        FCYAN = Fore.CYAN
        LCYAN = Fore.LIGHTCYAN_EX  # Underlined CYAN
        UCYAN = Fore.CYAN  # Blinking not directly supported, using CYAN

        # White Variants
        BWHITE = Fore.WHITE
        BBWHITE = Fore.WHITE  # Blinking not directly supported, using WHITE
        WHITE = Fore.WHITE
        DWHITE = Fore.WHITE  # Deep white (not distinct in colorama)
        FWHITE = Fore.WHITE  # Faint white (not distinct in colorama)
        IWHITE = Fore.WHITE  # Indented white (not distinct in colorama)
        LWHITE = Fore.WHITE  # Underlined white (not distinct in colorama)
        UWHITE = Fore.WHITE  # Blinking not directly supported, using WHITE


fg = ForegroundColor()
bg = BackgroundColor()
rs = fg.RESET


class OutputFormater:
    """ANSI styles for output display"""

    INFO = f"{fg.BLUE}[i]{rs}"
    WARN = f"{fg.YELLOW}[!]{rs}"
    ERR = f"{fg.RED}[x]{rs}"
    EXP = f"{fg.MAGENTA}[⁉️]{rs}"  # For exceptios
    OK = f"{fg.GREEN}[✓]{rs}"
    RESET = rs
