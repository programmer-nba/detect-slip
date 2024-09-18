import sqlite3 from "sqlite3";
sqlite3.verbose();

export const db = new sqlite3.Database("db.sqlite3");

export const TABLE_USERS = () => {
	db.run(
		`CREATE TABLE IF NOT EXISTS jwt  (
			token TEXT NOT NULL
		)`,
	);

	db.run(
		`CREATE TABLE IF NOT EXISTS pin  (
			data TEXT NOT NULL
		)`,
	);

	db.run(
		`CREATE TABLE IF NOT EXISTS device  (
			data TEXT NOT NULL
		)`,
	);

	db.run(
		`CREATE TABLE IF NOT EXISTS version  (
			data TEXT NOT NULL
		)`,
	);

	db.run(
		`CREATE TABLE IF NOT EXISTS access_token  (
			data TEXT NOT NULL
		)`,
	);
};

