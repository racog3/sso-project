-- -----------------------------------------------------
-- Schema ssodb
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `ssodb` DEFAULT CHARACTER SET utf8 ;
USE `ssodb` ;

-- -----------------------------------------------------
-- Table `ssodb`.`target_hosts`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `ssodb`.`target_hosts` (
  `target_host_id` INT(11) NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NOT NULL,
  `name` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`target_host_id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `ssodb`.`users`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `ssodb`.`users` (
  `username` VARCHAR(45) NOT NULL,
  `password` VARCHAR(45) NOT NULL,
  `enabled` TINYINT(4) NOT NULL DEFAULT '1',
  PRIMARY KEY (`username`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `ssodb`.`target_authorities`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `ssodb`.`target_authorities` (
  `target_authority_id` INT(11) NOT NULL,
  `username` VARCHAR(45) NOT NULL,
  `target_host_id` INT(11) NOT NULL,
  `role` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`target_authority_id`, `username`, `target_host_id`),
  INDEX `fk_target_authorities_users1_idx` (`username` ASC),
  INDEX `fk_target_authorities_target_hosts1_idx` (`target_host_id` ASC),
  CONSTRAINT `fk_target_authorities_target_hosts1`
    FOREIGN KEY (`target_host_id`)
    REFERENCES `ssodb`.`target_hosts` (`target_host_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_target_authorities_users1`
    FOREIGN KEY (`username`)
    REFERENCES `ssodb`.`users` (`username`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `ssodb`.`user_roles`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `ssodb`.`user_roles` (
  `user_role_id` INT(11) NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(45) NOT NULL,
  `role` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`user_role_id`),
  UNIQUE INDEX `uni_username_role` (`role` ASC, `username` ASC),
  INDEX `fk_username_idx` (`username` ASC),
  CONSTRAINT `fk_username`
    FOREIGN KEY (`username`)
    REFERENCES `ssodb`.`users` (`username`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;