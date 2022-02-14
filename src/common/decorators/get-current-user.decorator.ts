import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrrentUser = createParamDecorator(
  (data: undefined | string, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest();
    return request.user['sub'];
  },
);
