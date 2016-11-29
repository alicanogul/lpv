create database lpv;

grant all on lpv.* to 'root'@'localhost';

use lpv;

CREATE TABLE `users` (
  `username` VARCHAR(32) NOT NULL,
  `password` VARCHAR(256) DEFAULT NULL,
  PRIMARY KEY (`username`)
);

CREATE TABLE `userkeys` (
  `username` VARCHAR(32) NOT NULL,
  `public_key` MEDIUMTEXT DEFAULT NULL,
  `key_type` VARCHAR(16) DEFAULT "RSA",
  PRIMARY KEY (`username`)
);

CREATE TABLE `storedpasswords` (
  `domain` VARCHAR(32) NOT NULL,
  `description` VARCHAR(64) DEFAULT NULL,
  `cyphered_pass` MEDIUMTEXT DEFAULT NULL,
  PRIMARY KEY (`domain`)
);

CREATE TABLE `accesslists` (
  `domain` VARCHAR(32) NOT NULL,
  `username` VARCHAR(32) NOT NULL,
  `cyphered_key` MEDIUMTEXT DEFAULT NULL,
  PRIMARY KEY (`domain`,`username`)
);

CREATE TABLE `groups` (
  `username` VARCHAR(32) NOT NULL,
  `groupname` VARCHAR(32) NOT NULL,  
  PRIMARY KEY (`username`,`groupname`)
);

CREATE TABLE `groupacclists` (
  `groupname` VARCHAR(32) NOT NULL,  
  `domain` VARCHAR(32) NOT NULL,
  PRIMARY KEY (`groupname`,`domain`)
);

CREATE TABLE `globalcaps` (
  `username` VARCHAR(32) NOT NULL,
  `adduser` BOOL  DEFAULT NULL,
  `deluser`  BOOL DEFAULT NULL,
  `adddomain` BOOL DEFAULT NULL,
  `deldomain` BOOL DEFAULT NULL,
  `addgroup` BOOL DEFAULT NULL,
  `delgroup`  BOOL DEFAULT NULL,
  `adjust`  BOOL DEFAULT NULL,
  PRIMARY KEY (`username`)
);

CREATE TABLE `domaincaps` (
  `domain` VARCHAR(32) NOT NULL,
  `username` VARCHAR(32) NOT NULL,
  `changepass` BOOL  DEFAULT NULL,
  `allow`  BOOL DEFAULT NULL,
  `allowgroup`  BOOL DEFAULT NULL,
  `revokepass` BOOL DEFAULT NULL,
  `deldomain` BOOL DEFAULT NULL,
  `adjust`  BOOL DEFAULT NULL,
  PRIMARY KEY (`domain`, `username`)
);

CREATE TABLE `groupcaps` (
  `username` VARCHAR(32) NOT NULL,
  `groupname` VARCHAR(32) NOT NULL,
  `addtogroup` BOOL  DEFAULT NULL,
  `removefromgroup`  BOOL DEFAULT NULL,
  `delgroup`  BOOL DEFAULT NULL,
  `adjust`  BOOL DEFAULT NULL,
  PRIMARY KEY (`username`,`groupname`)
);

ALTER TABLE `users` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `userkeys` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `storedpasswords` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `accesslists` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `groups` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `groupacclists` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `globalcaps` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `domaincaps` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

ALTER TABLE `groupcaps` ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

INSERT INTO `users` (`username`, `password`) VALUES
('admin', '$2a$10$prdDGArihC6YlXzZlw7gI.l3KF7LGyoX6p3.rekpU4Fn2gxaLhxAu');

INSERT INTO `globalcaps` (`username`, `adduser`, `deluser`, `adddomain`, `deldomain`, `addgroup`, `delgroup`, `adjust` ) VALUES
('admin', 1, 1, 1, 1, 1, 1, 1);
