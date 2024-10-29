package com.ohgiraffers.session.user.model.dao;

import com.ohgiraffers.session.user.model.dto.AuthorityDTO;
import com.ohgiraffers.session.user.model.dto.SignupDTO;
import com.ohgiraffers.session.user.model.dto.UserAuthorityDTO;
import com.ohgiraffers.session.user.model.dto.UserDTO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {

    int regist(SignupDTO signupDTO);

    UserDTO findByUsername(String username);

    int findMaxUserCode();

    int registUserAuthority(UserAuthorityDTO userAuthorityDTO);

    List<AuthorityDTO> findAllAuthoritiesByUserCode(int userCode);
}
