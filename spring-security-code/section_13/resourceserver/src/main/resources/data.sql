DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS account_transactions;
DROP TABLE IF EXISTS loans;
DROP TABLE IF EXISTS cards;
DROP TABLE IF EXISTS notice_details;
DROP TABLE IF EXISTS contact_messages;

CREATE TABLE `accounts` (
   `account_number` int NOT NULL,
   `email` varchar(100) NOT NULL,
  `account_type` varchar(100) NOT NULL,
  `branch_address` varchar(200) NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`account_number`)
);

INSERT INTO `accounts` (`account_number`,`email`, `account_type`, `branch_address`, `create_dt`)
 VALUES (186576453,'accounts@eazybytes.com', 'Savings', '123 Main Street, New York', CURDATE());
 
CREATE TABLE `account_transactions` (
  `transaction_id` varchar(200) NOT NULL,
  `account_number` int NOT NULL,
  `email` varchar(100) NOT NULL,
  `transaction_dt` date NOT NULL,
  `transaction_summary` varchar(200) NOT NULL,
  `transaction_type` varchar(100) NOT NULL,
  `transaction_amt` int NOT NULL,
  `closing_balance` int NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`transaction_id`)
);

 
INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-7, 'Coffee Shop', 'Withdrawal', 30,34500,CURDATE()-7);

INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-6, 'Uber', 'Withdrawal', 100,34400,CURDATE()-6);

INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-5, 'Self Deposit', 'Deposit', 500,34900,CURDATE()-5);

INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-4, 'Ebay', 'Withdrawal', 600,34300,CURDATE()-4);

INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-2, 'OnlineTransfer', 'Deposit', 700,35000,CURDATE()-2);

INSERT INTO `account_transactions` (`transaction_id`, `account_number`, `email`, `transaction_dt`, `transaction_summary`, `transaction_type`,`transaction_amt`, 
`closing_balance`, `create_dt`)  VALUES (UUID(), 186576453, 'accounts@eazybytes.com', CURDATE()-1, 'Amazon.com', 'Withdrawal', 100,34900,CURDATE()-1);


CREATE TABLE `loans` (
  `loan_number` int NOT NULL AUTO_INCREMENT,
   `email` varchar(100) NOT NULL,
  `start_dt` date NOT NULL,
  `loan_type` varchar(100) NOT NULL,
  `total_loan` int NOT NULL,
  `amount_paid` int NOT NULL,
  `outstanding_amount` int NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`loan_number`)
);

INSERT INTO `loans` ( `email`, `start_dt`, `loan_type`, `total_loan`, `amount_paid`, `outstanding_amount`, `create_dt`)
 VALUES ( 'accounts@eazybytes.com', '2020-10-13', 'Home', 200000, 50000, 150000, '2020-10-13');
 
INSERT INTO `loans` ( `email`, `start_dt`, `loan_type`, `total_loan`, `amount_paid`, `outstanding_amount`, `create_dt`)
 VALUES ( 'accounts@eazybytes.com', '2020-06-06', 'Vehicle', 40000, 10000, 30000, '2020-06-06');
 
INSERT INTO `loans` ( `email`, `start_dt`, `loan_type`, `total_loan`, `amount_paid`, `outstanding_amount`, `create_dt`)
 VALUES ( 'accounts@eazybytes.com', '2018-02-14', 'Home', 50000, 10000, 40000, '2018-02-14');

INSERT INTO `loans` ( `email`, `start_dt`, `loan_type`, `total_loan`, `amount_paid`, `outstanding_amount`, `create_dt`)
 VALUES ( 'accounts@eazybytes.com', '2018-02-14', 'Personal', 10000, 3500, 6500, '2018-02-14');

CREATE TABLE `cards` (
  `card_id` int NOT NULL AUTO_INCREMENT,
  `card_number` varchar(100) NOT NULL,
   `email` varchar(100) NOT NULL,
  `card_type` varchar(100) NOT NULL,
  `total_limit` int NOT NULL,
  `amount_used` int NOT NULL,
  `available_amount` int NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`card_id`)
);

INSERT INTO `cards` (`card_number`, `email`, `card_type`, `total_limit`, `amount_used`, `available_amount`, `create_dt`)
 VALUES ('4565XXXX4656', 'accounts@eazybytes.com', 'Credit', 10000, 500, 9500, CURDATE());

INSERT INTO `cards` (`card_number`, `email`, `card_type`, `total_limit`, `amount_used`, `available_amount`, `create_dt`)
 VALUES ('3455XXXX8673', 'accounts@eazybytes.com', 'Credit', 7500, 600, 6900, CURDATE());
 
INSERT INTO `cards` (`card_number`, `email`, `card_type`, `total_limit`, `amount_used`, `available_amount`, `create_dt`)
 VALUES ('2359XXXX9346', 'accounts@eazybytes.com', 'Credit', 20000, 4000, 16000, CURDATE());
 
CREATE TABLE `notice_details` (
  `notice_id` int NOT NULL AUTO_INCREMENT,
  `notice_summary` varchar(200) NOT NULL,
  `notice_details` varchar(500) NOT NULL,
  `notic_beg_dt` date NOT NULL,
  `notic_end_dt` date DEFAULT NULL,
  `create_dt` date DEFAULT NULL,
  `update_dt` date DEFAULT NULL,
  PRIMARY KEY (`notice_id`)
);

INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('Home Loan Interest rates reduced', 'Home loan interest rates are reduced as per the goverment guidelines. The updated rates will be effective immediately', 
'2021-08-20', '2021-08-28', CURDATE(), null);

INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('Net Banking Offers', 'Customers who will opt for Internet banking while opening a saving account will get a $50 amazon voucher', 
'2021-08-20', '2021-08-28', CURDATE(), null);

INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('Mobile App Downtime', 'The mobile application of the EazyBank will be down from 2AM-5AM on 12/05/2020 due to maintenance activities', 
'2021-08-20', '2021-08-28', CURDATE(), null);

INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('E Auction notice', 'There will be a e-auction on 12/08/2020 on the Bank website for all the stubborn arrears.Interested parties can participate in the e-auction', 
'2021-08-20', '2021-08-28', CURDATE(), null);
   
INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('Launch of Millennia Cards', 'Millennia Credit Cards are launched for the premium customers of EazyBank. With these cards, you will get 5% cashback for each purchase', 
'2021-08-20', '2021-08-28', CURDATE(), null);

INSERT INTO `notice_details` ( `notice_summary`, `notice_details`, `notic_beg_dt`, `notic_end_dt`, `create_dt`, `update_dt`)
VALUES ('COVID-19 Insurance', 'EazyBank launched an insurance policy which will cover COVID-19 expenses. Please reach out to the branch for more details', 
'2021-08-20', '2021-08-28', CURDATE(), null);

CREATE TABLE `contact_messages` (
  `contact_id` varchar(50) NOT NULL,
  `contact_name` varchar(50) NOT NULL,
  `contact_email` varchar(100) NOT NULL,
  `subject` varchar(500) NOT NULL,
  `message` varchar(2000) NOT NULL,
  `create_dt` date DEFAULT NULL,
  PRIMARY KEY (`contact_id`)
);
