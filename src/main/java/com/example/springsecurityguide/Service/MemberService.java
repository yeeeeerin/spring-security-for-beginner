package com.example.springsecurityguide.Service;


import com.example.springsecurityguide.domain.Member;
import com.example.springsecurityguide.domain.MemberRole;
import com.example.springsecurityguide.domain.SecurityMember;
import com.example.springsecurityguide.repository.MemberRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@Transactional
public class MemberService implements UserDetailsService {

    @Autowired
    MemberRepository memberRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    public Member singUp(Member member){
        log.info(member.getEmail());
        member.setPassword(
                passwordEncoder.encode(member.getPassword())
        );
        member.setRole(MemberRole.USER);

        return memberRepository.save(member);
    }

    //todo 로그인 시 사용
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(email).get();

        if(member == null){
            throw new UsernameNotFoundException("회원이 없습니다.");
        }
        return SecurityMember.getMemberDetails(member);
    }

}
