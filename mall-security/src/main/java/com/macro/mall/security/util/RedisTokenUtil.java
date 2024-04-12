package com.macro.mall.security.util;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.macro.mall.common.service.RedisService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * JwtToken生成的工具类
 * JWT token的格式：header.payload.signature
 * header的格式（算法、token的类型）：
 * {"alg": "HS512","typ": "JWT"}
 * payload的格式（用户名、创建时间、生成时间）：
 * {"sub":"wang","created":1489079981393,"exp":1489684781}
 * signature的生成算法：
 * HMACSHA512(base64UrlEncode(header) + "." +base64UrlEncode(payload),secret)
 * Created by macro on 2018/4/26.
 */
//@Component
public class RedisTokenUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(RedisTokenUtil.class);
    private static final String CLAIM_KEY_USERNAME = "sub";
    private static final String CLAIM_KEY_CREATED = "created";
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Long expiration;
    @Value("${jwt.tokenHead}")
    private String tokenHead;
    @Autowired
    private RedisService redisService;
    @Value("${redis.database}")
    private String REDIS_DATABASE;
    @Value("${redis.expire.common}")
    private Long REDIS_EXPIRE;
    @Value("${redis.key.user}")
    private String REDIS_KEY_USER;

    /**
     * 从token中获取UserDetails
     */
    private UserDetails getUserDetailsFromToken(String token) {
        UserDetails userDetails = (UserDetails) redisService.get(REDIS_DATABASE + ":" + REDIS_KEY_USER + ":" + token);
        return userDetails;
    }

    /**
     * 生成token的过期时间
     */
    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    /**
     * 从token中获取登录用户名
     */
    public String getUserNameFromToken(String token) {
        Object value = redisService.get(REDIS_DATABASE + ":" + REDIS_KEY_USER + ":" + token);
        if (value == null) {
            return null;
        }
        JSONObject userDetails = JSON.parseObject((String) value);
        return userDetails.getString("username");
    }

    /**
     * 验证token是否还有效
     *
     * @param token       客户端传入的token
     * @param userDetails 从数据库中查询出来的用户信息
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = getUserNameFromToken(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * 判断token是否已经失效
     */
    private boolean isTokenExpired(String token) {
        Long expire = redisService.getExpire(REDIS_DATABASE + ":" + REDIS_KEY_USER + ":" + token);
        return expire <= 0;
    }


    /**
     * 根据用户信息生成token
     */
    public String generateToken(UserDetails userDetails) {
        String token = UUID.randomUUID().toString();
        String key = REDIS_DATABASE + ":" + REDIS_KEY_USER + ":" + token;
        redisService.set(key, JSON.toJSONString(userDetails), REDIS_EXPIRE);
        return token;
    }

    /**
     * 当原来的token没过期时是可以刷新的
     *
     * @param oldToken 带tokenHead的token
     */
    public String refreshHeadToken(String oldToken) {
        if (StrUtil.isEmpty(oldToken)) {
            return null;
        }
        String token = oldToken.substring(tokenHead.length());
        if (StrUtil.isEmpty(token)) {
            return null;
        }
        //token校验不通过
        UserDetails userDetails = getUserDetailsFromToken(token);
        if (Objects.isNull(userDetails)) {
            return null;
        }
        //如果token已经过期，不支持刷新
        if (isTokenExpired(token)) {
            return null;
        }
        //如果token在30分钟之内刚刷新过，返回原token
        if (tokenRefreshJustBefore(token, 30 * 60)) {
            return token;
        } else {
            // todo 旧的token还未删除, 待优化
            return generateToken(userDetails);
        }
    }

    /**
     * 判断token在指定时间内是否刚刚刷新过
     *
     * @param token 原token
     * @param time  指定时间（秒）
     */
    private boolean tokenRefreshJustBefore(String token, int time) {
        Long expire = redisService.getExpire(REDIS_DATABASE + ":" + REDIS_KEY_USER + ":" + token);
        return (REDIS_EXPIRE - expire) < time;
    }
}
