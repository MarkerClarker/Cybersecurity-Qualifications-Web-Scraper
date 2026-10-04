"""Main function of the Cybersecurity Job Qualifications and Skills Web Scraper (produces charts of the top certifications and skills sought by cybersecurity employers)"""

#imports
import time
from pathlib import Path

#imported modules and functions from said modules
from create_bar_chart import create_horizontal_bar_chart
from web_searching import (
    count_terms_once_per_page,
    links_from_search,
    qualifications_from_search,
    search_the_web,
    total_fail,
    total_success,
)

#ensures that the code can only be executed when the script is run directly
if __name__ == "__main__":
    
    # Define the folder where the program is located and where charts will be saved
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
        query_results = search_the_web(query,max_results=100)

        all_results.extend(query_results)
        time.sleep(0.2)

    links = links_from_search(all_results)

    print(f"Unique links collected: {len(links)}")
    print("Fetching certifications and skills...")


    fetch_start = time.perf_counter()

    records = qualifications_from_search(links)

    fetch_elapsed = time.perf_counter() - fetch_start

    print("\nExtracted records:")
    print(len(records))

    certification_counts, skill_counts = (count_terms_once_per_page(records))

    print()
    print("Preparing charts...")

    # Create the charts
    create_horizontal_bar_chart(
        frequencies=certification_counts,
        title="Top 20 Cybersecurity Certifications",
        xlabel="Number of mentions",
        filename=program_folder / "top_20_cybersecurity_certifications.png",
        top_n=20,
        color="darkorange",
    )

    print()
    print(f"Top 20 Cybersecurity Certifications saved to: {program_folder / 'top_20_cybersecurity_certifications.png'}")

    create_horizontal_bar_chart(
        frequencies=skill_counts,
        title="Top 30 Cybersecurity Skills and Tools",
        xlabel="Number of mentions",
        filename=program_folder / "top_30_cybersecurity_skills_and_tools.png",
        top_n=30,
        color="steelblue",
    )

    print()
    print(f"Top 30 Cybersecurity Skills and Tools saved to: {program_folder / 'top_30_cybersecurity_skills_and_tools.png'}")
    print("Charts have been created and saved.")
    print()
    print(f"Total pages attempted: {total_success + total_fail}")
    print(f"Total successful pages: {total_success}")
    print(f"Total failed pages: {total_fail}")