
//计算分为多少步骤
#define step 10e3
#include<stdio.h>
#include<stdlib.h>
#include<time.h>

//随机函数
double mysrand(int min,int max)
{
    if(max==min) return (double)min;

    static int last_rand=0;
    srand(time(0)+last_rand);
    int curret_rand=rand();
    last_rand=curret_rand;
    return  (double)(curret_rand%(max-min+1)+min);
}

struct node
{
    double x;
    double y;
};
typedef struct node node_t;

struct line
{
    node_t node1;
    node_t node2;
};
typedef struct line line_t;

double fun(node_t node)
{
    return node.x*node.y;
}

void find_max(line_t line,node_t* max_node,double *max_value, line_t * max_line)
{
    /*
    根据step规定的步数，求出步差
    */
    double step_x=(line.node2.x-line.node1.x)/step;
    double step_y=(line.node2.y-line.node1.y)/step;
    /*
    根据步差求出最大值的点
    */
    int i=0;
    for(i=1; i<step; i++)
    {
        node_t node_temp= {line.node1.x+i*step_x,line.node1.y+i*step_y};
        double temp_value=fun(node_temp);
        if(temp_value>*max_value)
        {
            *max_value=temp_value;
            *max_node=node_temp;
            *max_line=line;
        }
    }

    /*
    计算两个端点的值，并取最大
    */
    double node1_value=fun(line.node1);
    double node2_value=fun(line.node2);
    if(node1_value>*max_value)
    {
        *max_value=node1_value;
        *max_node=line.node1;
        *max_line=line;
    }
    if(node2_value>*max_value)
    {
        *max_value=node2_value;
        *max_node=line.node2;
        *max_line=line;
    }

    /*
    计算中点特殊点
    */
    node_t node_temp= {(line.node1.x+line.node2.x)/2,(line.node1.y+line.node2.y)/2};
    double temp_value=fun(node_temp);
    if(temp_value>*max_value)
    {
        *max_value=temp_value;
        *max_node=node_temp;
        *max_line=line;
    }
}

#define print 1
//返回选择的边
int nash2(const double a[],const double b[],const int size)
{
    int i,j;
    double select_probability[size];
#if print==1
    for(i=0; i<size; i++)
    {
        printf("%.2f ",a[i]);
    }
    printf("\n");

    for(i=0; i<size; i++)
    {
        printf("%.2f ",b[i]);
    }
    printf("\n");
#endif // print
    node_t max_node= {0,0};
    double max_value=0;
    line_t max_line;

    int frequency[size];
    for(i=0; i<size; i++)
    {
        frequency[i]=1;
    }
    for(i=0; i<size-1; i++)
    {
        for( j=i+1; j<size; j++)
        {
            if(
                (a[i]-a[j]<0.001)
                && (a[i]-a[j]>-0.001)
                && (b[i]-b[j]>-0.001)
                && (b[i]-b[j]<0.001)
            )
            {
                frequency[i]++;
                frequency[j]++;
            }
        }
    }

    if(frequency[0]==size)
    {
        int i;
        for(i=0; i<size; i++)
        {
            select_probability[i]=1.0/size;
        }
#if print==1
        for(i=0; i<size; i++)
        {
            printf("%.2f,%.2f  ",a[i],b[i]);
        }printf("\n");

        for(i=0; i<size; i++)
        {
             printf("%.2f  ",select_probability[i]);

        }printf("\n");
#endif // print
        return ;
    }

    double p_a[size];
    double p_b[size];
    /*求出到数的和*/
    double a_reciprocal_sum=0,b_reciprocal_sum=0;
    for(i=0; i<size; i++)
    {
        a_reciprocal_sum+= 1/a[i];
        b_reciprocal_sum+= 1/b[i];
    }
    /*求出对应的选择概率*/
    for(i=0; i<size; i++)
    {
        p_a[i]= (1/b[i])/b_reciprocal_sum;
        p_b[i]= (1/a[i])/a_reciprocal_sum;
#if print==1
        printf("%f %f\n",p_a[i],p_b[i]);
#endif // print
    }
    double nash_a=0,nash_b=0;
    /*根据期望求出下边界*/
    for(i=0; i<size; i++)
    {
        nash_a=nash_a+p_a[i]*p_b[i]*a[i];
        nash_b=nash_b+p_a[i]*p_b[i]*b[i];
    }

#if print==1
    printf("nash_Profit:(%.2f,%.2f)\n",nash_a,nash_b);
#endif // print

    node_t node_first= {0,0};
    node_t node_second= {0,0};
    for(i=0; i<size; i++)
    {
        node_t temp= {a[i],b[i]};

        if(temp.x-node_first.x >-0.001&& temp.x-node_first.x<0.001
                && temp.y-node_first.y >-0.001&& temp.y-node_first.y<0.001)
        {
            continue;
        }
        if(temp.x-node_second.x >-0.001&& temp.x-node_second.x<0.001
                && temp.y-node_second.y >-0.001&& temp.y-node_second.y<0.001)
        {
            continue;
        }

        if(fun(temp)>fun(node_first))
        {
            node_second=node_first;
            node_first=temp;
        }
        else if(fun(temp)>fun(node_second))
        {
            node_second=temp;
        }
    }


    line_t line1=
    {
        node_first,
        node_second
    };
    find_max(line1,&max_node,&max_value,&max_line);

#if print==1
    printf("max_value=%.2f \nnash_node=(%.2f,%.2f)\n",max_value,max_node.x,max_node.y);
    printf("nash_node=(%.2f,%.2f)\n",max_node.x,max_node.y);
    printf("line:(%.2f,%.2f)-->(%.2f,%.2f)\n",max_line.node1.x,max_line.node1.y,max_line.node2.x,max_line.node2.y);
#endif // print

        /*
    aX+bY=c
    dX+eY=f
    X=(ce-bf)/(ae-bd)
    Y=(af-cd)/(ae-bd)
    */
    double c=max_node.x;
    double f=max_node.y;
    double aa=max_line.node1.x;
    double bb=max_line.node2.x;
    double d=max_line.node1.y;
    double e=max_line.node2.y;

    double X,Y;
    if(aa*e-bb*d >-10e-3 &&aa*e-bb*d <10e-3){
        X=1;
        Y=0;
    }else{
       X=(c*e-bb*f)/(aa*e-bb*d);
        Y=(aa*f-c*d)/(aa*e-bb*d);
    }
    for(i=0; i<size; i++)
    {
        if(max_line.node1.x-a[i]<10e-3 && max_line.node1.y-b[i]<10e-3&&X>10e-3
                &&max_line.node1.x-a[i]>-10e-3 && max_line.node1.y-b[i]>-10e-3)
        {
            select_probability[i]=X;
        }
        else if(max_line.node2.x-a[i]<10e-3&&max_line.node2.y-b[i]<10e-3&&Y>10e-3
                &&max_line.node2.x-a[i]>-10e-3&&max_line.node2.y-b[i]>-10e-3)
        {
            select_probability[i]=Y;
        }
        else
        {
            select_probability[i]=0;
        }
    }



    for(i=0; i<size; i++)
    {
        select_probability[i]=select_probability[i]/frequency[i];
    }
#if print==1
    for(i=0; i<size; i++)
    {
         printf("%.2f  ",select_probability[i]);
    }
    printf("\n");
#endif // print

    double number=mysrand(0,99);
    double sum=0;
    for(i=0;i<size;i++){

        sum=sum+select_probability[i]*100;
        if(sum>=number){
            break;
        }
    }
    return i;

}
