# Web Security Base

这是一个基于 Spring Boot 的 Web 安全基础项目，集成了多种安全认证和授权机制。

## 技术栈

- **核心框架**: Spring Boot 2.7.18
- **安全框架**: Spring Security
- **持久层**: MyBatis
- **数据库**: MySQL 8.0
- **缓存**: Redis
- **认证方式**:
  - JWT (JSON Web Token)
  - OAuth2
- **开发工具**: Lombok

## 主要特性

- 基于 Spring Security 的安全框架
- JWT 认证支持
- OAuth2 第三方登录集成
- Redis 缓存支持
- MyBatis 数据库访问
- RESTful API 设计

## 项目结构

```
src/
├── main/
│   ├── java/          # Java 源代码
│   └── resources/     # 配置文件
```

## 环境要求

- JDK 17+
- Maven 3.6+
- MySQL 8.0+
- Redis

## 快速开始

1. 克隆项目
```bash
git clone [repository-url]
```

2. 配置数据库
- 创建 MySQL 数据库

```sql
CREATE TABLE `users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `roles` varchar(255) DEFAULT NULL,
  `auth_type` varchar(20) DEFAULT 'LOCAL' COMMENT '认证类型：LOCAL-本地认证/GITHUB-GitHub认证',
  `github_id` varchar(100) DEFAULT NULL COMMENT 'GitHub用户ID',
  `email` varchar(100) DEFAULT NULL COMMENT '用户邮箱',
  `avatar_url` varchar(255) DEFAULT NULL COMMENT '用户头像URL',
  `github_username` varchar(100) DEFAULT NULL COMMENT 'GitHub用户名',
  `last_login_time` datetime DEFAULT NULL COMMENT '最后登录时间',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `uk_github_id` (`github_id`),
  UNIQUE KEY `uk_email` (`email`),
  KEY `idx_auth_type` (`auth_type`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COMMENT='用户表';
```

- 修改 `application.properties` 中的数据库连接信息

3. 配置 Redis
- 确保 Redis 服务已启动
- 修改 `application.properties` 中的 Redis 连接信息

4. 构建项目
```bash
mvn clean install
```

5. 运行项目
```bash
mvn spring-boot:run
```

## 配置说明

主要配置文件位于 `src/main/resources/application.properties`，包含：
- 数据库连接配置
- Redis 配置
- JWT 配置
- OAuth2 配置
- 其他应用配置

## 安全特性

- 基于 JWT 的认证机制
- OAuth2 第三方登录支持
- 密码加密存储
- 会话管理
- 跨域支持

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。

## 许可证

[MIT License](LICENSE)    