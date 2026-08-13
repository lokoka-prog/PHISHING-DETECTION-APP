import imaplib
import email
from email.header import decode_header
import logging

# Configure logging for debugging and audit reporting
logging.basicConfig(
    filename="email_fetcher.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def decode_mime_words(header_value):
    """Helper to decode MIME encoded headers into standard strings."""
    if not header_value:
        return ""
    decoded_fragments = decode_header(header_value)
    header_str = ""
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            header_str += fragment.decode(encoding or "utf-8", errors="ignore")
        else:
            header_str += str(fragment)
    return header_str

def extract_body(msg):
    """Optimized payload decoding to handle plain text and HTML payloads efficiently."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Skip attachments and process text content
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                    break  # Prefer plain text if available
            elif content_type == "text/html" and "attachment" not in content_disposition and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
            
    return body

def fetch_latest_emails(server, port, user, password, folder="INBOX", limit=5):
    """Connects via IMAP, fetches unread emails, logs operational details, and decodes content."""
    emails = []
    try:
        logging.info(f"Connecting to IMAP server: {server}:{port}")
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        mail.select(folder)

        # Search for unread emails
        status, response = mail.search(None, "UNSEEN")
        if status != "OK":
            logging.warning("Failed to search unread emails.")
            return [], "Failed to retrieve unread emails."

        mail_ids = response[0].split()
        latest_ids = mail_ids[-limit:] if len(mail_ids) >= limit else mail_ids

        logging.info(f"Found {len(mail_ids)} unread email(s). Processing latest {len(latest_ids)}.")

        for email_id in reversed(latest_ids):
            status, data = mail.fetch(email_id, "(RFC822)")
            if status != "OK":
                logging.error(f"Failed to fetch email ID: {email_id.decode()}")
                continue

            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_mime_words(msg.get("Subject"))
            sender = decode_mime_words(msg.get("From"))
            body = extract_body(msg)

            emails.append({
                "id": email_id.decode(),
                "sender": sender,
                "subject": subject,
                "body": body
            })

        mail.logout()
        logging.info("IMAP session closed successfully.")
        return emails, None

    except imaplib.IMAP4.error as imap_err:
        err_msg = f"IMAP authentication or protocol error: {str(imap_err)}"
        logging.error(err_msg)
        return [], err_msg
    except Exception as e:
        err_msg = f"Unexpected error while fetching emails: {str(e)}"
        logging.error(err_msg)
        return [], err_msg