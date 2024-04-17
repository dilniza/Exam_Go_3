CREATE TABLE "Users" (
  "id" uuid PRIMARY KEY,
  "mail" VARCHAR(50) UNIQUE,
  "first_name" VARCHAR(50) NOT NULL,
  "last_name" VARCHAR(50),
  "password" VARCHAR(255) NOT NULL,
  "phone" VARCHAR(20) UNIQUE,
  "sex" VARCHAR(20) NOT NULL,
  "active" BOOLEAN NOT NULL DEFAULT true,
  "created_at" TIMESTAMP,
  "updated_at" TIMESTAMP
);