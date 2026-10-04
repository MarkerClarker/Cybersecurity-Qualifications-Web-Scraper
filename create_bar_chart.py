"""A function that creates a horizontal bar chart of a given frequency `Counter` and saves it as a PNG file."""

#imports Python libraries

from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


#create a horizontal bar chart with the required parameters and saves it to a png file
def create_horizontal_bar_chart(frequencies: Counter[str],title: str,xlabel: str,filename: str,top_n: int,color: str,) -> None:
    """Creates a horizontal bar chart with the required parameters and saves it to a PNG file."""
    top_items = frequencies.most_common(top_n)
    if not top_items:
        print(f"No data available for {title}")
        return

    #reverse the order of the top items for horizontal bar chart
    names = [name for name, count in top_items][::-1]
    counts = [count for name, count in top_items][::-1]

    plt.figure(figsize=(13, 9))
    bars = plt.barh(names,counts,color=color,)
    plt.title(title, fontsize=18)
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel("")

    # Add count labels to the bars.
    for bar, count in zip(bars, counts):
        plt.text(
            bar.get_width() + 0.1,
            bar.get_y() + bar.get_height() / 2,
            str(count),
            va="center",
            fontsize=10,
        )

    plt.tight_layout()
    program_folder = Path(__file__).resolve().parent
    output_path = program_folder / filename

    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"Chart saved to: {output_path}")
    plt.show()