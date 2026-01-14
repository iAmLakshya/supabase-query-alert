CREATE EXTENSION IF NOT EXISTS pgaudit;

ALTER ROLE postgres SET pgaudit.log TO 'all';
ALTER ROLE postgres SET pgaudit.log_parameter TO on;
