import argparse
import datetime
from functools import cache, partial
import humanhash
import ipaddress
import os
import pyshark
import queue
import re
from sqlalchemy import Integer, String
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import sessionmaker, scoped_session
import sys, tty, termios, select
import time
import timeago
import threading
import xdg.BaseDirectory


PROGRAM_NAME = "owl"
PROGRAM_DESCRIPTION = "monitor Online Windows Laptops on the local network 🦉"
DEFAULT_CACHE_FILENAME = "cache.sqlite"

PRIVATE_IPV4_CLASSES = [
    ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0")),
    ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0")),
    ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0")),
]

# TODO python package; versions in deps
# TODO and timezones
# TODO compact db


class Base(DeclarativeBase):
    pass


class LogEntry(Base):
    __tablename__ = "log_entry"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[int] = mapped_column(Integer)
    ip: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String)


def sniff_and_queue_packets(q: queue.Queue, interface: str, user_display_filter: str):
    base_display_filter = "(browser) and (browser.command == 0x02)"
    if user_display_filter:
        display_filter = f"({base_display_filter}) and ({user_display_filter})"
    else:
        display_filter = base_display_filter
    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter="udp and port 138",
        display_filter=display_filter,
    )
    for packet in capture.sniff_continuously():
        timestamp = packet.sniff_time
        ip = packet.ip.src
        computer_name = packet.browser.response_computer_name
        q.put((timestamp, ip, computer_name))


def save_to_database(q: queue.Queue, session_factory):
    with session_factory() as session:
        while True:
            item = q.get()
            if item is None:
                q.task_done()
                return
            timestamp, ip, computer_name = item
            timestamp = int(timestamp.timestamp())
            entry = LogEntry(timestamp=timestamp, ip=ip, name=computer_name)
            session.add(entry)
            session.commit()
            q.task_done()


clear_screen = partial(print, "\033c\033[3J", end="")


def pretty_print_table(column_names, rows, alignment=None, file=None):
    if alignment is None:
        alignment = {}
    # alignment = {'id': '>', 'name': '<', 'score': '>'}
    # TODO show function

    # Compute column widths (max of header and each cell string)
    widths = {}
    for col, name in column_names.items():
        col_values = (str(row[col]) for row in rows)
        widths[col] = max(len(name), *(len(v) for v in col_values))

    # Build format strings per column
    fmts = {
        col: f"{{:{alignment.get(col,'<')}{widths[col]}}}"
        for col in column_names.keys()
    }

    # Print header
    header = " | ".join(fmts[col].format(name) for col, name in column_names.items())
    sep = "-+-".join("-" * widths[col] for col in column_names.keys())
    print(header, file=file)
    print(sep, file=file)

    # Print rows
    for r in rows:
        print(
            " | ".join(fmts[n].format(str(r[n])) for n in column_names.keys()),
            file=file,
        )


@cache
def anonimize_computer_name(name):
    return humanhash.humanize(name.encode("utf-8").hex(), words=1).upper() + "-LT"


@cache
def anonimize_ip_address(ip):
    """
    Anonyimizes an IPv4 address with the following algorithm:
    - if the address is public, replace all the octects with 'XXX';
    - if the address is private, replace all the octects that are not
      common to all addresses of the given private class with 'XXX'.
    e.g. '1.1.1.1'      is anonymized as 'XXX.XXX.XXX.XXX'
         '10.42.0.1'    is anonymized as '10.XXX.XXX.XXX'
         '172.16.0.32'  is anonymized as '172.XXX.XXX.XXX'
         '192.168.0.12' is anonymized as '192.168.XXX.XXX'
    """
    ip_address = ipaddress.ip_address(ip)
    if ip_address.is_private:
        (class_,) = (c for c in PRIVATE_IPV4_CLASSES if ip_address in c)
        prefix_len_bits = class_.prefixlen
    else:
        prefix_len_bits = 0
    prefix_len_octets = prefix_len_bits // 8
    octects = ip.split(".")
    for i in range(prefix_len_octets, 4):
        octects[i] = "XXX"
    return ".".join(octects)


COLUMNS = {
    "n": {"short_description": "computer name", "long_description": "computer name"},
    "i": {"short_description": "IP address", "long_description": "IP address"},
    "T": {
        "short_description": "timestamp",
        "long_description": "timestamp of last seen",
    },
    "I": {
        "short_description": "last seen at",
        "long_description": "last seen in ISO 8601 format",
    },
    "A": {
        "short_description": "last seen",
        "long_description": 'last seen in "time ago" format',
    },
}


def visualize_data(
    session_factory, sleep_interval, columns, anonymize=False, locale=None
):
    from sqlalchemy import select, func, desc
    from sqlalchemy.orm import aliased
    from sqlalchemy.sql import over

    row_number = (
        func.row_number()
        .over(partition_by=LogEntry.name, order_by=LogEntry.timestamp.desc())
        .label("rn")
    )

    subq = select(LogEntry, row_number).subquery()
    alias = aliased(LogEntry, subq)

    stmt = select(alias).where(subq.c.rn == 1).order_by(subq.c.timestamp.desc())

    with session_factory() as session:
        while True:
            results = session.execute(stmt).scalars().all()

            now = datetime.datetime.now()
            format_name = lambda name: (
                anonimize_computer_name(name) if anonymize else name
            )
            format_ip = lambda ip: (anonimize_ip_address(ip) if anonymize else ip)
            format_last_seen_at = lambda t: t.isoformat()
            format_last_seen_ago = lambda t: timeago.format(t, now, locale=locale)

            column_names = {col: COLUMNS[col]["short_description"] for col in columns}
            rows = [
                (last_seen := datetime.datetime.fromtimestamp(e.timestamp))
                and {
                    "n": format_name(e.name),
                    "i": format_ip(e.ip),
                    "T": e.timestamp,
                    "I": format_last_seen_at(last_seen),
                    "A": format_last_seen_ago(last_seen),
                }
                for e in results
            ]
            clear_screen()
            pretty_print_table(column_names, rows)
            time.sleep(sleep_interval)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description=PROGRAM_DESCRIPTION,
        epilog="press q or CTRL+C to quit",
    )
    p.add_argument(
        "-i",
        "--interface",
        default="any",
        help="name or idx of interface (default: any)",
        metavar="CAPTURE_INTERFACE",
    )
    p.add_argument(
        "-f",
        "--filter",
        help="packet filter in libpcap filter syntax",
        metavar="CAPTURE_FILTER",
        dest="display_filter",
    )
    p.add_argument(
        "-a",
        action="store_true",
        default=False,
        help="anonymize computer names and IP addresses",
        dest="anonymize",
    )

    def columns(string):
        pattern = f"^[{''.join(c for c in COLUMNS.keys())}]+$"
        if not re.match(pattern, string):
            raise argparse.ArgumentTypeError(
                f"'{string}' is not a valid list of columns"
            )
        return string

    p.add_argument(
        "-c",
        "--columns",
        default="niA",
        type=columns,
        help="columns to show ("
        + ", ".join(
            f"{col}: {attrs['long_description']}" for col, attrs in COLUMNS.items()
        )
        + "; default: niA)",
    )
    p.add_argument(
        "-n",
        "--interval",
        default=2,
        type=int,
        help="specify visualization update interval (default: 2)",
        metavar="SECONDS",
    )
    p.add_argument(
        "-l",
        "--locale",
    )
    cache_group = p.add_mutually_exclusive_group()
    cache_group.add_argument(
        "-C",
        "--cache",
        help=f"defaults to $XDG_CACHE_HOME/{PROGRAM_NAME}/{DEFAULT_CACHE_FILENAME}",
        dest="cache_file",
    )
    cache_group.add_argument(
        "--no-cache",
        action="store_false",
        help="do not read or write to a cache file",
        dest="cache_file",
    )
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.cache_file is False:
        engine = create_engine("sqlite:///:memory:")
    else:
        if args.cache_file:
            cache_file = args.cache_file
        else:
            cache_dir = xdg.BaseDirectory.save_cache_path(PROGRAM_NAME)
            cache_file = f"{cache_dir}/{DEFAULT_CACHE_FILENAME}"
        engine = create_engine(f"sqlite:///{cache_file}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    Session = scoped_session(session_factory)

    q = queue.Queue()
    sniffer = threading.Thread(
        target=sniff_and_queue_packets,
        args=(q, args.interface, args.display_filter),
        daemon=True,
    )
    processor = threading.Thread(target=save_to_database, args=(q, Session))
    visualizer = threading.Thread(
        target=visualize_data,
        args=(Session, args.interval, args.columns, args.anonymize, args.locale),
        daemon=True,
    )

    def key_pressed():
        return select.select([sys.stdin], [], [], 0)[0]

    def stop():
        q.put(None)
        processor.join()
        exit(0)

    try:
        sniffer.start()
        processor.start()
        visualizer.start()

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        while True:
            if key_pressed():
                if sys.stdin.read(1).lower() == "q":
                    stop()

        # q.join()
        # sniffer.join()
        # processor.join()
        # visualizer.join()

    except KeyboardInterrupt:
        stop()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


if __name__ == "__main__":
    main()
