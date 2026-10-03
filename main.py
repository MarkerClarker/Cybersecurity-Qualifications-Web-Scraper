"""Cybersecurity Job Qualifications and Skills Scraper (produces a CSV and a chart of the top certifications and skills)"""

#imports Python libraries
import time
from pathlib import Path

#the important stuff for web scraping, and HTML parsing, and charting
import pandas as pd
from bar_chart import create_horizontal_bar_chart
from web_searching import (
    count_terms_once_per_page,
    links_from_search,
    qualifications_from_search,
    search_the_web,
    total_fail,
    total_success,
)

if __name__ == "__main__":
    """# Main function, full of function calls to search the web, extract qualifications, count certifications and skills, and create CSV 
    files and charts. The if __name__ == "__main__": block ensures that the code is only executed when the script is run directly."""

    program_folder = Path(__file__).resolve().parent

    queries = [
        # Cybersecurity Analyst
    "Cybersecurity Analyst job qualifications",
    "Cybersecurity Analyst job technical skills",
    "Cybersecurity Analyst job education requirements",
    "Cybersecurity Analyst job resume skills",
    "Cybersecurity Analyst job certifications",

    # SOC Analyst
    "SOC Analyst job qualifications",
    "SOC Analyst job education requirements",
    "SOC Analyst job certifications",

    # Information Security Analyst
    "Information Security Analyst job qualifications",
    "Information Security Analyst job education requirements",
    "Information Security Analyst job certifications",
    "Information Security Analyst job resume skills",

    # Penetration Testing
    "Penetration Tester job qualifications",
    "Penetration testing job certifications required",

    # Cloud Security
    "Cloud Security Analyst job qualifications",
    "Cloud security job certifications required",

    # Network security
    "Network Security Analyst job qualifications",
    "Network security job certifications required",

    # Security architecture
    "Security Architect job qualifications",
    "Cybersecurity architecture job certifications",

    # Entry-level and junior roles
    "Entry level cybersecurity job qualifications",

    # General skills
    "Cybersecurity jobs technical skills",

    ]

    all_results: list[dict[str, str]] = []

    for query in queries:
        query_results = search_the_web(
            query,
            max_results=100,
        )

        all_results.extend(query_results)

        time.sleep(0.2)

    links = links_from_search(all_results)

    print(f"Unique links collected: {len(links)}")
    print("Fetching certifications and skills...")


    fetch_start = time.perf_counter()

    records = qualifications_from_search(links)

    fetch_elapsed = time.perf_counter() - fetch_start

    #print the average time per link if there are any links, mainly for diagnostic purposes
    if links:
        print(
            f"Average time per link: "
            f"{fetch_elapsed / len(links):.2f} seconds"
        )   

    print("\nExtracted records:")
    print(len(records))

    certification_counts, skill_counts = (
        count_terms_once_per_page(records)
    )

    print("\nCertifications:")
    for certification, count in certification_counts.most_common():
        print(f"{certification}: {count}")
    print("\nSkills and technologies:")
    for skill, count in skill_counts.most_common():
        print(f"{skill}: {count}")

    # Create the certification CSV
    certification_table = pd.DataFrame(
        certification_counts.most_common(),
        columns=["Certification", "Mentions"],
    )

    certification_table.insert(
        0,
        "Rank",
        range(1, len(certification_table) + 1),
    )

    certification_table.to_csv(
        program_folder / "top_20_certifications.csv",
        index=False,
    )

    # Create the skills CSV
    skill_table = pd.DataFrame(
        skill_counts.most_common(),
        columns=["Skill_or_Tool", "Mentions"],
    )

    skill_table.insert(
        0,
        "Rank",
        range(1, len(skill_table) + 1),
    )

    skill_table.to_csv(
        program_folder / "top_30_cybersecurity_skills_and_tools.csv",
        index=False,
    )

    # Create the charts
    create_horizontal_bar_chart(
        frequencies=certification_counts,
        title="Top 20 Cybersecurity Certifications",
        xlabel="Number of mentions",
        filename=program_folder / "top_20_cybersecurity_certifications.png",
        top_n=20,
        color="darkorange",
    )

    create_horizontal_bar_chart(
        frequencies=skill_counts,
        title="Top 30 Cybersecurity Skills and Tools",
        xlabel="Number of mentions",
        filename=program_folder / "top_30_cybersecurity_skills_and_tools.png",
        top_n=30,
        color="steelblue",
    )

    print("\nTop certifications:")
    print(certification_table.to_string(index=False))

    print("\nTop skills and tools:")
    print(skill_table.to_string(index=False))

    print()
    print(
        f"Total pages attempted: "
        f"{total_success + total_fail}"
    )
    print(f"Total successful pages: {total_success}")
    print(f"Total failed pages: {total_fail}")