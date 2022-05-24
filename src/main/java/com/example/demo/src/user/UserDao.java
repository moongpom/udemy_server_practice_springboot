package com.example.demo.src.user;


import com.example.demo.src.user.model.GetUserFeedRes;
import com.example.demo.src.user.model.GetUserInfoRes;
import com.example.demo.src.user.model.GetUserPostsRes;
import com.example.demo.src.user.model.GetUserRes;
import com.example.demo.src.user.model.PatchUserReq;
import com.example.demo.src.user.model.PostUserReq;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.util.List;


@Repository
public class UserDao {

    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setDataSource(DataSource dataSource){
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public GetUserInfoRes selectUserInfo(int userIdx){
        String selectUsersInfoQuery = "SELECT u.userIdx as userIdx,\n" +
            "            u.nickName as nickName,\n" +
            "            u.name as name,\n" +
            "            u.profileImgUrl as profileImgUrl,\n" +
            "            u.website as website,\n" +
            "            u.introduction as introduction,\n" +
            "            IF(followerCount is null, 0, followerCount) as followerCount,\n" +
            "            If(followingCount is null, 0, followingCount) as followingCount,\n" +
            "            count(p.postIdx) as postCount\n" +
            "        FROM User as u\n" +
            "            join Post as p on p.userIdx = u.userIdx and p.status = 'ACTIVE'\n" +
            "            left join (select followerIdx, count(followIdx) as followerCount from Follow WHERE status = 'ACTIVE' group by followIdx) fc on fc.followerIdx = u.userIdx\n" +
            "            left join (select followeeIdx, count(followIdx) as followingCount from Follow WHERE status = 'ACTIVE' group by followIdx) f on f.followeeIdx = u.userIdx\n" +
            "        WHERE u.userIdx = ? and u.status = 'ACTIVE'";
        int selectUserInfoParam = userIdx;
        return this.jdbcTemplate.queryForObject(selectUsersInfoQuery,
                (rs,rowNum) -> new GetUserInfoRes(
                    rs.getInt("userIdx"),
                    rs.getString("nickName"),
                    rs.getString("name"),
                    rs.getString("profileImgUrl"),
                    rs.getString("website"),
                    rs.getString("introduction"),
                    rs.getInt("followerCount"),
                    rs.getInt("followingCount"),
                    rs.getInt("postCount")
                ),selectUserInfoParam);
    }

    //유저 정보로 게시물 반환
    public List<GetUserPostsRes> selectUserPosts(int userIdx){
        String selectUserPostsQuery =
            "        SELECT p.postIdx as postIdx,\n" +
                "            pi.imgUrl as postImgUrl\n" +
                "        FROM Post as p\n" +
                "            join PostImgUrl as pi on pi.postIdx = p.postIdx and pi.status = 'ACTIVE'\n" +
                "            join User as u on u.userIdx = p.userIdx\n" +
                "        WHERE p.status = 'ACTIVE' and u.userIdx = ?\n" +
                "        group by p.postIdx\n" +
                "        HAVING min(pi.postImgUrlIdx)\n" +
                "        order by p.postIdx; " ;
        int selectUserPostsParam = userIdx;
        return this.jdbcTemplate.query(selectUserPostsQuery,
            (rs,rowNum) -> new GetUserPostsRes(
                rs.getInt("postIdx"),
                rs.getString("postImgUrl")
            ),selectUserPostsParam);
    }


/*
    public GetUserFeedRes getUsersByEmail(String email){
        String getUsersByEmailQuery = "select userIdx,name,nickName,email from User where email=?";
        String getUsersByEmailParams = email;
        return this.jdbcTemplate.queryForObject(getUsersByEmailQuery,
                (rs, rowNum) -> new GetUserRes(
                        rs.getInt("userIdx"),
                        rs.getString("name"),
                        rs.getString("nickName"),
                        rs.getString("email")),
                getUsersByEmailParams);
    }

*/
    public GetUserRes getUsersByIdx(int userIdx){
        String getUsersByIdxQuery = "select userIdx,name,nickName,email from User where userIdx=?;";
        int getUsersByIdxParams = userIdx;
        return this.jdbcTemplate.queryForObject(getUsersByIdxQuery,
                (rs, rowNum) -> new GetUserRes(
                        rs.getInt("userIdx"),
                        rs.getString("name"),
                        rs.getString("nickName"),
                        rs.getString("email")),
                getUsersByIdxParams);
    }


    public int createUser(PostUserReq postUserReq){
        System.out.println("여긴 userdao");
        String createUserQuery = "insert into User(name, nickName,  introduction, email, pwd) VALUES (?,?,?,?,?);";
        Object[] createUserParams = new Object[]{postUserReq.getName(), postUserReq.getNickName(),postUserReq.getIntroduction(), postUserReq.getEmail(), postUserReq.getPwd()};
        System.out.println("createUserParams "+ createUserParams);
        this.jdbcTemplate.update(createUserQuery, createUserParams);
        String lastInsertIdQuery = "select last_insert_id()";
        System.out.println("lastInserIdQuery 오륜가");
        return this.jdbcTemplate.queryForObject(lastInsertIdQuery,int.class);
    }

    public int checkEmail(String email){
        String checkEmailQuery = "select exists(select email from User where email = ?)";
        String checkEmailParams = email;
        return this.jdbcTemplate.queryForObject(checkEmailQuery,
                int.class,
                checkEmailParams);

    }

    public int checkUserExist(int userIdx){
        String checkUserExistQuery = "select exists(select userIdx from User where userIdx = ?)";
        int checkUserExistParams = userIdx;
        return this.jdbcTemplate.queryForObject(checkUserExistQuery,
            int.class,
            checkUserExistParams);

    }


    public int modifyUserName(PatchUserReq patchUserReq){
        String modifyUserNameQuery = "update User set nickName = ? where userIdx = ? ";
        Object[] modifyUserNameParams = new Object[]{patchUserReq.getNickName(), patchUserReq.getUserIdx()};

        return this.jdbcTemplate.update(modifyUserNameQuery,modifyUserNameParams);
    }

    // Delete User
    public int deleteUser(int userId) {
        String deleteUserByIdQuery = "delete from User where userIdx = ?";
        int deleteUsersByIdParams = userId;
        return this.jdbcTemplate.update(deleteUserByIdQuery,deleteUsersByIdParams);
    }


}
