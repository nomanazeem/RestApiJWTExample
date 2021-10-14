-- MySQL dump 10.13  Distrib 5.7.9, for Win64 (x86_64)
--
-- Host: localhost    Database: vuejs_jwt_springboot
-- ------------------------------------------------------
-- Server version	5.7.23

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `role_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `role`
--

LOCK TABLES `role` WRITE;
INSERT INTO `role` VALUES (1,'USER'),(2,'MODERATOR'),(3,'ADMIN');
UNLOCK TABLES;

--
-- Table structure for table `todo`
--

DROP TABLE IF EXISTS `todo`;
CREATE TABLE `todo` (
  `id_todo` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) DEFAULT NULL,
  `status` varchar(100) DEFAULT NULL,
  `is_deleted` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id_todo`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `todo`
--

LOCK TABLES `todo` WRITE;
INSERT INTO `todo` VALUES (1,'This is Task 1.2','Active',0),(2,'This is task 2','Pending',0),(3,'This is task 3.33233','Banned',0),(4,'This is task 4.1','Pending',0),(10,'Pakistan Task 2','Banned',0),(9,'Pakistan Task','Pending',0),(12,'New Record 1','Banned',0),(8,'Chicken boti','Active',0),(13,'New Record 2','Active',0),(14,'Azeem Ullah','Pending',0);
UNLOCK TABLES;

--
-- Table structure for table `user_roles`
--

DROP TABLE IF EXISTS `user_roles`;
CREATE TABLE `user_roles` (
  `user_id` bigint(20) NOT NULL,
  `role_id` bigint(20) NOT NULL,
  PRIMARY KEY (`user_id`,`role_id`),
  KEY `FKrhfovtciq1l558cw6udg0h0d3` (`role_id`),
  CONSTRAINT `FKhfh9dx7w3ubf1co1vdev94g3f` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `FKrhfovtciq1l558cw6udg0h0d3` FOREIGN KEY (`role_id`) REFERENCES `role` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `user_roles`
--

LOCK TABLES `user_roles` WRITE;
INSERT INTO `user_roles` VALUES (1,3),(2,3),(3,3),(4,3),(5,3);
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `email` varchar(50) DEFAULT NULL,
  `password` varchar(120) DEFAULT NULL,
  `username` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UKr43af9ap4edm43mmtq01oddj6` (`username`),
  UNIQUE KEY `UK6dotkott2kjsp8vw4d0m25fb7` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES (1,'syed.noman.azeem@gmail.com','$2a$10$y.oa67WwdDQQDJC4fqbknebMG/1VDDz3ZEB31huUw1.fvy2bEkvhK','nazeem'),(2,'saleemraza@gmail.com','$2a$10$k5q.LoFlzU6sK6DvO//xcunzyxxeDarB.c07q5.oJgs.Ky.mQ4T.S','saleemraza'),(3,'asifkhan@gmail.com','$2a$10$8fk4YFdwbKrToDrSbfjHeec1XQ3Ok7xhjWUMAhxObsZu5qDGoTlha','asifkhan'),(4,'ayyanazeem@gmail.com','$2a$10$SajRa2XMIqbhVFW5e9komeN5gYSY93UGgJU2dhQVrG8VTS8mZ1edK','ayyanazeem'),(5,'azeem123@gmail.com','$2a$10$Z6x0aLImtv.YDre1wf77vuTUlUPzD7N2.JNWQU/95gE6bKuFMaRyy','azeem123');
UNLOCK TABLES;


-- Dump completed on 2021-10-12 16:19:36
