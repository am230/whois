import click


@click.command()
@click.argument("domain")
def main(domain: str):
    from .whois import whois_lookup

    print(whois_lookup(domain))


if __name__ == "__main__":
    main()
