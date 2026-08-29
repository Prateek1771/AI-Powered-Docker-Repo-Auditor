import sys

from app.queue.producer import enqueue_scan


def main() -> None:
    target = sys.argv[1]

    message = enqueue_scan("demo-tenant", target.split(":")[0], target)

    print(f"enqueued {message.job_id}")


if __name__ == "__main__":
    main()
