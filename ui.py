import pyfiglet
from rich.text import Text
from rich.console import Console

def gradient_text(ascii_art, start_color=(255, 0, 0), end_color=(0, 0, 255)):
    gradient = Text()
    lines = ascii_art.splitlines()
    total_lines = len(lines)
    for i, line in enumerate(lines):
        ratio = i / total_lines
        r, g, b = [int(start + (end - start) * ratio) for start, end in zip(start_color, end_color)]
        gradient.append(line + "\n", style=f"rgb({r},{g},{b})")
    return gradient

def print_ascii_art(console):
    ascii_art = pyfiglet.figlet_format("pySearch")
    colored_ascii = gradient_text(ascii_art, start_color=(255, 0, 0), end_color=(0, 0, 255))
    console.print(colored_ascii)