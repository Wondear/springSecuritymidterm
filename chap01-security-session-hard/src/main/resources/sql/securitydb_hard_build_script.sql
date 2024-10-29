-- 0) SQL 쿼리를 실행할 타겟 스키마(securitydb) 선택
-- USE securitydb;


-- 1) 테이블 생성
DROP TABLE IF EXISTS tbl_user_role CASCADE;
DROP TABLE IF EXISTS tbl_user CASCADE;
DROP TABLE IF EXISTS tbl_authority CASCADE;

-- tbl_authority(권한) 테이블 생성
CREATE TABLE IF NOT EXISTS tbl_authority
(
    -- COLUMN LEVEL CONSTRAINTS
    authority_code INT AUTO_INCREMENT COMMENT '권한식별코드',
    authority_name VARCHAR(255) NOT NULL COMMENT '권한명',
    authority_desc VARCHAR(255) NOT NULL COMMENT '권한설명',
    -- TABLE LEVEL CONSTRAINTS
    CONSTRAINT pk_authority_code PRIMARY KEY (authority_code)
) ENGINE=INNODB COMMENT '권한';

-- tbl_user(사용자정보) 테이블 생성
CREATE TABLE IF NOT EXISTS tbl_user
(
    -- COLUMN LEVEL CONSTRAINTS
    user_code INT AUTO_INCREMENT COMMENT '사용자식별코드',
    username VARCHAR(30) NOT NULL COMMENT '사용자아이디',
    password VARCHAR(100) NOT NULL COMMENT '사용자비밀번호',
    full_name VARCHAR(30) COMMENT '사용자이름',
    -- TABLE LEVEL CONSTRAINTS
    CONSTRAINT pk_category_code PRIMARY KEY (user_code)
) ENGINE=INNODB COMMENT '사용자정보';

-- tbl_user_role(사용자별권한) 테이블 생성
CREATE TABLE IF NOT EXISTS tbl_user_role
(
    -- COLUMN LEVEL CONSTRAINTS
    user_code INT AUTO_INCREMENT COMMENT '사용자식별코드',
    authority_code INT NOT NULL COMMENT '권한식별코드',
    -- TABLE LEVEL CONSTRAINTS
    CONSTRAINT pk_user_role PRIMARY KEY (user_code, authority_code),
    CONSTRAINT fk_user_code FOREIGN KEY (user_code) REFERENCES tbl_user (user_code),
    CONSTRAINT fk_authority_code FOREIGN KEY (authority_code) REFERENCES tbl_authority (authority_code)
) ENGINE=INNODB COMMENT '사용자별권한';


-- 2) 테이블 생성 결과 조회
# SHOW TABLES;


-- 3) 더미 데이터 삽입
INSERT INTO tbl_authority (authority_name, authority_desc) VALUES ('ADMIN', '관리자');
INSERT INTO tbl_authority (authority_name, authority_desc) VALUES ('USER', '일반사용자');

-- PW: admin
INSERT INTO tbl_user (username, password, full_name)
VALUES ('admin', '$2a$10$0/P7ioMJGLEBGelrtU8VPO3ULwhW/XcgOPAQw7g0I2jXlmYBTf1rq', '어두민');
-- PW: pass01
INSERT INTO tbl_user (username, password, full_name)
VALUES ('user01', '$2a$10$NtNLV.LF.ok2FYw1zq54lecv0UHb0HKGgWwjgTgu56DqXvAXrKkMS', '홍길동');

-- 사용자 '어두민'은 ADMIN 및 USER 권한 모두를 가짐.
INSERT INTO tbl_user_role (user_code, authority_code) VALUES (1, 1);
INSERT INTO tbl_user_role (user_code, authority_code) VALUES (1, 2);
-- 사용자 '홍길동'은 USER 권한을 가짐.
INSERT INTO tbl_user_role (user_code, authority_code) VALUES (2, 2);