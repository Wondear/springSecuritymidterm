package com.ohgiraffers.session.auth.model.service;

import com.ohgiraffers.session.user.model.dto.AuthorityDTO;
import com.ohgiraffers.session.user.model.dto.UserDTO;
import com.ohgiraffers.session.user.model.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class AuthService implements UserDetailsService {

    /* 설명. UserDetailsService:
     *  Security에서 사용자의 아이디를 인증하기 위한 인터페이스다.
     *  loadUserByUsername() 메서드를 필수로 구현해야 하며,
     *  로그인 인증 시 해당 메서드에 login 요청 시 전달된 사용자의 id를 매개변수로 DB에서 조회한다.
     * */

    @Autowired
    private UserService userService;

    /* 설명.
     *  Spring Security의 인증 과정에서 사용자 정보를 불러오는 역할을 수행하는 메서드로,
     *  (참고: 정확히는 사용자가 로그인을 시도하는 시점에 DaoAuthenticationProvider가 이 메서드를 호출함)
     *  form login 요청 시, 전달 인자로 받은 username을 기반으로 데이터베이스나 다른 저장소에서 사용자 정보를 조회한다.
     *  이 메서드는 사용자의 자격 증명과 권한 정보를 담은 객체를 반환하며 UserDetails를 구현한 구현체가 되어야 한다.
     *  여기서는 UserDTO가 이 UserDetails를 구현한 구현체이기 때문에
     *  DB에서 조회된 결과를 그대로 UserDTO에 매핑시킨 후, 해당 UserDTO 인스턴스를 반환하면 된다.
     * */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        /* 목차. 1. tbl_user 테이블로부터 주어진 username으로 레코드 검색 */
        UserDTO foundUser = userService.findByUsername(username);
        System.out.println("#1. username으로 검색된 사용자 : " + foundUser);

        if (Objects.isNull(foundUser)) {
            throw new UsernameNotFoundException("회원정보가 존재하지 않습니다.");
        }

        /* 목차. 2. 검색된 사용자의 PK 값을 사용해 tbl_user_role 테이블로부터 해당 사용자가 인가받을 수 있는 모든 권한을 조회 */
        int userCode = foundUser.getUserCode();
        List<AuthorityDTO> authorities = userService.findAllAuthoritiesByUserCode(userCode);
        System.out.println("#2. 사용자가 인가받을 권한 : " + authorities);

        /* 목차. 3. 사용자가 인가받을 모든 권한(List<UserRole>)을 foundUser에 추가 */
        foundUser.setUserAuthorities(authorities);
        System.out.println("#3. 완성된 UserDetails 타입의 사용자 정보 : " + foundUser);

        /* 목차. 4. 사용자의 모든 인증/인가 정보가 담긴 UserDetails 타입의 데이터 반환 */
        return foundUser;
    }
}
