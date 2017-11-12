-- -----------------------------------------------------
-- Spring Security related tables and roles (roles which it has in SSO server Security Context)
-- -----------------------------------------------------

SET @user1 = 'user1@etfbl.net', @user2 = 'user2@etfbl.net', @pass1 = 1234, @pass2=1234;
SET @host1Url = 'http://localhost:8081/sp1', @host2Url = 'http://localhost:8082/sp2';

INSERT INTO `ssodb`.`users` (`username`, `password`, `enabled`) VALUES (@user1, @pass1, '1');
INSERT INTO `ssodb`.`users` (`username`, `password`, `enabled`) VALUES (@user2, @pass2, '1');

INSERT INTO `ssodb`.`user_roles` (`username`, `role`) VALUES (@user1, 'ROLE_USER');
INSERT INTO `ssodb`.`user_roles` (`username`, `role`) VALUES (@user2, 'ROLE_USER');

-- -----------------------------------------------------
-- SSO service tables and roles (roles which it has n requested Service Provider - SP application)
-- -----------------------------------------------------
INSERT INTO `ssodb`.`target_hosts` (`url`, `name`) VALUES (@host1Url, 'SP1');
INSERT INTO `ssodb`.`target_hosts` (`url`, `name`) VALUES (@host2Url, 'SP2');

-- user1 has access to protected resource on both SSO client apss (SP's)
INSERT INTO `ssodb`.`target_authorities` (`username`, `target_host_id`, `role`) VALUES
    (@user1, (SELECT `target_host_id` FROM `ssodb`.`target_hosts` WHERE `url` = @host1Url) , 'ROLE_USER');
INSERT INTO `ssodb`.`target_authorities` (`username`, `target_host_id`, `role`) VALUES
    (@user1, (SELECT `target_host_id` FROM `ssodb`.`target_hosts` WHERE `url` = @host2Url) , 'ROLE_USER');

-- user2 has access to protected resource only on 2nd SSO client app (SP2)
INSERT INTO `ssodb`.`target_authorities` (`username`, `target_host_id`, `role`) VALUES
    (@user2, (SELECT `target_host_id` FROM `ssodb`.`target_hosts` WHERE `url` = @host1Url) , 'ROLE_GUEST');
INSERT INTO `ssodb`.`target_authorities` (`username`, `target_host_id`, `role`) VALUES
    (@user2, (SELECT `target_host_id` FROM `ssodb`.`target_hosts` WHERE `url` = @host2Url) , 'ROLE_USER');