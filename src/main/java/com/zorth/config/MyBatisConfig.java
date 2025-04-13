package com.zorth.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@MapperScan("com.zorth.mapper")  // 扫描包下的所有 Mapper 接口
public class MyBatisConfig {

}
