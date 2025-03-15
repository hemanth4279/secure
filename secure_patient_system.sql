-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: secure_patient_db
-- ------------------------------------------------------
-- Server version	8.0.41-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `appointments`
--

DROP TABLE IF EXISTS `appointments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `appointments` (
  `appointment_id` int NOT NULL AUTO_INCREMENT,
  `patient_id` varchar(50) DEFAULT NULL,
  `doctor_id` varchar(50) DEFAULT NULL,
  `appointment_date` date DEFAULT NULL,
  `appointment_time` time DEFAULT NULL,
  `reason` text,
  `status` enum('Pending','Confirmed','Cancelled','Accepted','Rejected') DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `video_call_url` varchar(255) DEFAULT NULL,
  `transaction_id` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`appointment_id`),
  KEY `patient_id` (`patient_id`),
  KEY `appointments_ibfk_2` (`doctor_id`),
  CONSTRAINT `appointments_ibfk_1` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`patient_id`),
  CONSTRAINT `appointments_ibfk_2` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`doctor_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `appointments`
--

LOCK TABLES `appointments` WRITE;
/*!40000 ALTER TABLE `appointments` DISABLE KEYS */;
INSERT INTO `appointments` VALUES (16,'PID727785','DD704318','2025-03-13','00:03:00','gh','Confirmed','2025-03-12 18:31:19','7ba06e8b4aa140c0937cde923d27e64d','67d033309bdf7');
/*!40000 ALTER TABLE `appointments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `doctor_medicines`
--

DROP TABLE IF EXISTS `doctor_medicines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `doctor_medicines` (
  `id` int NOT NULL AUTO_INCREMENT,
  `doctor_id` int NOT NULL,
  `patient_id` int NOT NULL,
  `medicine_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `doctor_id` (`doctor_id`),
  KEY `patient_id` (`patient_id`),
  KEY `medicine_id` (`medicine_id`),
  CONSTRAINT `doctor_medicines_ibfk_1` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`id`) ON DELETE CASCADE,
  CONSTRAINT `doctor_medicines_ibfk_2` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE,
  CONSTRAINT `doctor_medicines_ibfk_3` FOREIGN KEY (`medicine_id`) REFERENCES `medicines` (`medicine_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `doctor_medicines`
--

LOCK TABLES `doctor_medicines` WRITE;
/*!40000 ALTER TABLE `doctor_medicines` DISABLE KEYS */;
/*!40000 ALTER TABLE `doctor_medicines` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `doctor_patient`
--

DROP TABLE IF EXISTS `doctor_patient`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `doctor_patient` (
  `doctor_id` varchar(50) NOT NULL,
  `patient_id` varchar(50) NOT NULL,
  `status` varchar(20) DEFAULT 'active',
  PRIMARY KEY (`doctor_id`,`patient_id`),
  KEY `patient_id` (`patient_id`),
  CONSTRAINT `doctor_patient_ibfk_1` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`doctor_id`),
  CONSTRAINT `doctor_patient_ibfk_2` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`patient_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `doctor_patient`
--

LOCK TABLES `doctor_patient` WRITE;
/*!40000 ALTER TABLE `doctor_patient` DISABLE KEYS */;
INSERT INTO `doctor_patient` VALUES ('DD704318','PID727785','active'),('DD872507','PID584060','active'),('DD899380','PID584060','active'),('DD899380','PID727785','active');
/*!40000 ALTER TABLE `doctor_patient` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `doctor_requests`
--

DROP TABLE IF EXISTS `doctor_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `doctor_requests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `doctor_id` varchar(50) DEFAULT NULL,
  `patient_id` varchar(50) DEFAULT NULL,
  `status` varchar(20) DEFAULT 'pending',
  `decryption_key` text,
  `request_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `doctor_id` (`doctor_id`),
  KEY `patient_id` (`patient_id`),
  CONSTRAINT `doctor_requests_ibfk_1` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`doctor_id`),
  CONSTRAINT `doctor_requests_ibfk_2` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`patient_id`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `doctor_requests`
--

LOCK TABLES `doctor_requests` WRITE;
/*!40000 ALTER TABLE `doctor_requests` DISABLE KEYS */;
INSERT INTO `doctor_requests` VALUES (1,'DD872507','PID563224','accepted','706136c48b2d0d86f470fcc939689f0b','2025-03-13 07:49:47'),(2,'DD872507','PID727785','accepted','6a63fb57993981bdf231bfc8470f3bba','2025-03-13 07:50:55'),(3,'DD704318','PID584060','accepted','48c2598c3fb918568046ae46c34447d4','2025-03-13 08:01:05'),(4,'DD899380','PID563224','accepted','2743ee2f681f03ab1eb2d3aa1dbaeaee','2025-03-13 08:22:04'),(5,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 08:36:46'),(6,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 08:37:22'),(7,'DD704318','PID563224','rejected',NULL,'2025-03-13 08:39:18'),(8,'DD704318','PID563224','accepted','cENhcG8rREpuYkcrbFdVeVhFSW92dWV1U2JWWlZodWdXVW1Xd0tkOTkxRWdQT1NV','2025-03-13 08:39:45'),(9,'DD704318','PID563224','rejected',NULL,'2025-03-13 08:43:35'),(10,'DD704318','PID563224','accepted','cENhcG8rREpuYkcrbFdVeVhFSW92dWV1U2JWWlZodWdXVW1Xd0tkOTkxRWdQT1NV','2025-03-13 08:44:07'),(11,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 08:44:53'),(12,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 08:45:46'),(13,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 08:46:26'),(14,'DD704318','PID126228','rejected',NULL,'2025-03-13 08:53:44'),(15,'DD704318','PID126228','rejected',NULL,'2025-03-13 08:56:15'),(16,'DD704318','PID126228','rejected',NULL,'2025-03-13 08:56:20'),(17,'DD704318','PID126228','rejected',NULL,'2025-03-13 09:01:05'),(18,'DD704318','PID563224','accepted','MVFCdEVsSTFPVDNFdEtvQ05YLzBUVUd1T1M5bGlQcXlGVzAxUlRUeEhpS3RtcEVYdTdlMTQwRzlFM1V0MlhFaVF0a0QyUXk0VmV4aTdpeXhSeDZodWlXWFAxczhROGZUNTRyV1puUEIzNFZmajVBS09VQm4zZG1SdWg0bnNRaFg0aFd2eGdhd29MYkhjMnFGM0cvWUM0enRWbis1','2025-03-13 09:01:18'),(19,'DD704318','PID563224','rejected',NULL,'2025-03-13 09:02:04');
/*!40000 ALTER TABLE `doctor_requests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `doctors`
--

DROP TABLE IF EXISTS `doctors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `doctors` (
  `id` int NOT NULL AUTO_INCREMENT,
  `doctor_id` varchar(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone` varchar(15) NOT NULL,
  `specialization` varchar(100) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `is_activated` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`doctor_id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `phone` (`phone`),
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `doctors`
--

LOCK TABLES `doctors` WRITE;
/*!40000 ALTER TABLE `doctors` DISABLE KEYS */;
INSERT INTO `doctors` VALUES (23,'DD051303','drhemanth','vtu24064@veltech.edu.in','8125507026','heart','1234',1,1),(17,'DD704318','guduru Hemanth kumar reddy','hemanth42079@gmail.com','944186135','Cardiologist','1234',1,1),(21,'DD872507','vinnela','vinnela@gmail.com','9441861880','puls','1234',1,1),(22,'DD899380','peter','peter@gmail.com','8441861353','heart','1234',1,1),(20,'DD967641','pavani','pavani@gmail.com','9441861367','heart','1234',1,1);
/*!40000 ALTER TABLE `doctors` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `keys`
--

DROP TABLE IF EXISTS `keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patient_id` int DEFAULT NULL,
  `aes_key` text,
  `rsa_public_key` text,
  `rsa_private_key` text,
  `dsa_signature` text,
  PRIMARY KEY (`id`),
  KEY `patient_id` (`patient_id`),
  CONSTRAINT `keys_ibfk_1` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `keys`
--

LOCK TABLES `keys` WRITE;
/*!40000 ALTER TABLE `keys` DISABLE KEYS */;
/*!40000 ALTER TABLE `keys` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `medical_records`
--

DROP TABLE IF EXISTS `medical_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `medical_records` (
  `id` int NOT NULL AUTO_INCREMENT,
  `patient_id` varchar(20) DEFAULT NULL,
  `blood_group` varchar(5) DEFAULT NULL,
  `blood_pressure` varchar(10) DEFAULT NULL,
  `body_temp` varchar(10) DEFAULT NULL,
  `pulse_rate` varchar(10) DEFAULT NULL,
  `previous_medications` text,
  `updated_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `encrypted_data` text,
  `used` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `patient_id` (`patient_id`)
) ENGINE=InnoDB AUTO_INCREMENT=36 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `medical_records`
--

LOCK TABLES `medical_records` WRITE;
/*!40000 ALTER TABLE `medical_records` DISABLE KEYS */;
INSERT INTO `medical_records` VALUES (32,'PID727785','O+','120','96','140','no','2025-03-12 17:01:03','cwR5lH0F6zP5JDhNO2vl3R16uv+2AVSgvs2aUCGm3ts=',0),(33,'PID727785',NULL,NULL,NULL,NULL,NULL,'2025-03-12 17:00:46','zzxLMydAAMd3vmASDTXCY/R0iejw5kFcnEY9m6rY3sNb',0),(34,'PID584060','O+','120','80','dfgh','                                        bhji\r\n                                    ','2025-03-13 08:36:29','MydNC5iuwqiGmsh8MXYxmCkYU1EfKJ5BpFJgdFf6Nl180a2NstQkyXf2GiWixO5HwoRUjfV9QwYDhDgYcCel03NJKpSzADVZJjBYPu4iophOGID81tGGjvakQhBMsDlPpVyTm9fV4wr2ZAAETRU4xys=',0),(35,'PID563224','O+','120','80','140','                                        pavani no\r\n                                    ','2025-03-13 08:45:37','1QBtElI1OT3EtKoCNX/0TUGuOS9liPqyFW01RTTxHiKtmpEXu7e140G9E3Ut2XEiQtkD2Qy4Vexi7iyxRx6huiWXP1s8Q8fT54rWZnPB34Vfj5AKOUBn3dmRuh4nsQhX4hWvxgawoLbHc2qF3G/YC4ztVn+5',0);
/*!40000 ALTER TABLE `medical_records` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `medicines`
--

DROP TABLE IF EXISTS `medicines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `medicines` (
  `medicine_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `brand` varchar(100) DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `expiry_date` date DEFAULT NULL,
  `description` text,
  PRIMARY KEY (`medicine_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `medicines`
--

LOCK TABLES `medicines` WRITE;
/*!40000 ALTER TABLE `medicines` DISABLE KEYS */;
INSERT INTO `medicines` VALUES (1,'Paracetamol','Cipla','Painkiller',50.00,'2026-12-31','Used for fever and pain relief'),(2,'Ibuprofen','Sun Pharma','Painkiller',80.00,'2025-08-15','Anti-inflammatory medicine'),(3,'Amoxicillin','GSK','Antibiotic',120.00,'2027-06-20','Used to treat bacterial infections'),(4,'Cetirizine','Ranbaxy','Antihistamine',30.00,'2025-03-10','Used for allergies'),(5,'Metformin','Dr. Reddy\'s','Diabetes',150.00,'2027-09-01','Used for type 2 diabetes management');
/*!40000 ALTER TABLE `medicines` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `orders` (
  `order_id` int NOT NULL AUTO_INCREMENT,
  `patient_id` int NOT NULL,
  `doctor_id` int NOT NULL,
  `order_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `total_price` decimal(10,2) DEFAULT NULL,
  `status` enum('Pending','Completed','Cancelled') DEFAULT 'Pending',
  PRIMARY KEY (`order_id`),
  KEY `patient_id` (`patient_id`),
  KEY `doctor_id` (`doctor_id`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE,
  CONSTRAINT `orders_ibfk_2` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `patients`
--

DROP TABLE IF EXISTS `patients`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `patients` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `dob` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `address` text,
  `is_activated` tinyint(1) DEFAULT '0',
  `patient_id` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  KEY `patient_id` (`patient_id`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `patients`
--

LOCK TABLES `patients` WRITE;
/*!40000 ALTER TABLE `patients` DISABLE KEYS */;
INSERT INTO `patients` VALUES (18,'guduru hemanth kumar reddy','9441861353','hemanth42079@gmail.com','2025-02-07','scrypt:32768:8:1$lpRq3ISYgLOp3yHO$6bdf3918de73af1b79867f34bc22ed12e20c8d0ab5326d0a8443a0e23430a9751c8043d48f2ed1e11241361689f49f59c57ffdd0bee211f359c57a1d9106a6c4','Thotla palle',1,'PID727785'),(20,'Jhon','0441861353','jhon@gmail.com','1983-03-10','scrypt:32768:8:1$JMFI0Pq9EnYjlYVs$997620ef0b14a97c8f29bbe8766b79d1324de5860abf965fde6742903fd47a00e34eb8dcf464b45c95b3df8c0e090e49c88865be82a59a0dc107e8b21f17d637','Thotla palle\r\nB. Mattam',1,'PID584060'),(21,'joe','2441861353','joe@gmail.com','2025-03-10','scrypt:32768:8:1$Y5WtFg5SQ6nmmfp7$810460776df6c96ad95e4f0c8b150942c2c8c5010b28c84654e6015342a3ce345547c318b4a3a5f37ee59921eca8815f79614cc58772c756093ddffd7594b045','dfcghjkl;',1,'PID317961'),(22,'pavani','9441861351','pavani@gmail.com','2004-08-03','scrypt:32768:8:1$yHD43UyAP78cQRxk$62091745069bdb9c64996d71174b415a38a7706b2cc274c17651154510d480455ac11757ef776d9634dc3e33a5f5729ab2f814cf71c40792915f442cadd0424f','garalladhinna',1,'PID563224'),(23,'joes','9441861534','joes@gmail.com','1999-03-04','scrypt:32768:8:1$Cyruf7nnjtVCUuN4$1bfd3f36dee902dcc7ef150c281f508f54052025ab0845e4c155b05dfad168e3dff4c527d6fe25fd23ca547b38614c3fee6a35253d779bbe41420eb3e729a5df','Mydukur',1,'PID126228'),(27,'hemanthrdj','8125507026','vtu24064@veltech.edu.in','2002-01-08','scrypt:32768:8:1$ZfbwHuo0LeZ10n6t$86b7f4915d854ab62781b349ca69ebf93851f70b612a5b9012c01756115ef8fd8b69d7100dd5dd5d0719d6115bc8db924afbc9c9b690a4c190bd3c162db9719e','Ramulavari street,somireddypalli\r\nBrahmam gari mattam mandal',1,'PID876944'),(28,'new hemanth','0812550702','hemanthrdj@gmail.com','2000-12-02','scrypt:32768:8:1$Lr06GxgTij18juBT$b106d964deec5327a781f26e3fc7fa9cbf50bfd8f2894aacb127462ef8d66b3c9b75df48182a066dd52b103352eb274395e91e8912a7fc6c893a8a242ab16251','new',1,'PID182964');
/*!40000 ALTER TABLE `patients` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `upi_transactions`
--

DROP TABLE IF EXISTS `upi_transactions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `upi_transactions` (
  `transaction_id` int NOT NULL AUTO_INCREMENT,
  `order_id` int NOT NULL,
  `patient_id` int NOT NULL,
  `upi_id` varchar(50) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `status` enum('Pending','Success','Failed') DEFAULT 'Pending',
  `transaction_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`transaction_id`),
  KEY `order_id` (`order_id`),
  KEY `patient_id` (`patient_id`),
  CONSTRAINT `upi_transactions_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`order_id`) ON DELETE CASCADE,
  CONSTRAINT `upi_transactions_ibfk_2` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `upi_transactions`
--

LOCK TABLES `upi_transactions` WRITE;
/*!40000 ALTER TABLE `upi_transactions` DISABLE KEYS */;
/*!40000 ALTER TABLE `upi_transactions` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-03-14 14:27:09
