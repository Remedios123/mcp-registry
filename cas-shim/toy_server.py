"""自测用玩具 MCP 后端:两个工具,无鉴权,端口 8002。"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("toy", host="127.0.0.1", port=8002, stateless_http=True)


@mcp.tool()
def toy_echo(text: str) -> str:
    """原样返回输入文本,用于验证聚合端点的调用路由。"""
    return f"echo: {text}"


@mcp.tool()
def toy_add(a: int, b: int) -> int:
    """两数相加,用于验证参数透传。"""
    return a + b


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
