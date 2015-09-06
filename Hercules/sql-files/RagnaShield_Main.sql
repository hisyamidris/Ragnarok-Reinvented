CREATE TABLE IF NOT EXISTS `ragnashield_banlist` (
  `mac` VARCHAR(240) NOT NULL DEFAULT '',
  `cpu_id` VARCHAR(240) NOT NULL DEFAULT '',
  `drive_id` VARCHAR(240) NOT NULL DEFAULT '',
  `motherboard_id` VARCHAR(240) NOT NULL DEFAULT '',
  `btime` DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
  `rtime` DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
  `issuer_group_id` TINYINT(3) NOT NULL DEFAULT '0',
  `reason` VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`mac`, `cpu_id`, `drive_id`, `motherboard_id`)
) ENGINE=MyISAM;

ALTER TABLE `login`
ADD (last_mac varchar(18)  NOT NULL DEFAULT '', last_cpu varchar(37) NOT NULL DEFAULT '', last_drive varchar(9) NOT NULL DEFAULT '', last_motherboard varchar(20) NOT NULL DEFAULT '')